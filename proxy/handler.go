package proxy

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/cert"
	"github.com/haxii/fastproxy/client"
	"github.com/haxii/fastproxy/transport"
	"github.com/haxii/fastproxy/util"
)

//Handler proxy handler
type Handler struct {
	//HTTPSDecryptEnable test if host's https connection should be decrypted
	ShouldDecryptHost func(host string) bool
	//URLProxy url specified proxy, nil path means this is a un-decrypted https traffic
	URLProxy func(hostWithPort string, path []byte) *client.SuperProxy
	//MitmCACert HTTPSDecryptCACert ca.cer used for https decryption
	MitmCACert *tls.Certificate
}

func (h *Handler) handleHTTPConns(c net.Conn, req *Request,
	bufioPool *bufiopool.Pool, sniffer Sniffer, client *client.Client) error {
	//set requests proxy
	req.SetProxy(h.URLProxy(req.HostWithPort(), req.reqLine.Path()))
	//convert c into a http response
	writer := bufioPool.AcquireWriter(c)
	defer bufioPool.ReleaseWriter(writer)
	defer writer.Flush()
	resp := AcquireResponse()
	defer ReleaseResponse(resp)
	if err := resp.InitWithWriter(writer, sniffer); err != nil {
		return err
	}

	//handle http proxy request
	if err := client.Do(req, resp); err != nil {
		return err
	}
	return nil
}

func (h *Handler) handleHTTPSConns(c net.Conn, hostWithPort string,
	bufioPool *bufiopool.Pool, sniffer Sniffer, client *client.Client) error {
	if h.ShouldDecryptHost(hostWithPort) {
		return h.decryptConnect(c, hostWithPort, bufioPool, sniffer, client)
	}
	return h.tunnelConnect(c, bufioPool, hostWithPort)
}

func (h *Handler) sendHTTPSProxyStatusOK(c net.Conn) (err error) {
	return util.WriteWithValidation(c, []byte("HTTP/1.1 200 OK\r\n\r\n"))
}

func (h *Handler) sendHTTPSProxyStatusBadGateway(c net.Conn) (err error) {
	return util.WriteWithValidation(c, []byte("HTTP/1.1 501 Bad Gateway\r\n\r\n"))
}

//proxy https traffic directly
func (h *Handler) tunnelConnect(conn net.Conn,
	bufioPool *bufiopool.Pool, hostWithPort string) error {
	superProxy := h.URLProxy(hostWithPort, nil)
	var (
		tunnelConn net.Conn
		err        error
	)
	if superProxy != nil {
		//acquire server conn to target host
		tunnelConn, err = superProxy.MakeHTTPTunnel(bufioPool, hostWithPort)
	} else {
		//acquire server conn to target host
		tunnelConn, err = transport.Dial(hostWithPort)
	}

	if err != nil {
		h.sendHTTPSProxyStatusBadGateway(conn)
		return util.ErrWrapper(err, "error occurred when dialing to host "+hostWithPort)
	}
	defer tunnelConn.Close()

	//handshake with client
	if err := h.sendHTTPSProxyStatusOK(conn); err != nil {
		return util.ErrWrapper(err, "error occurred when handshaking with client")
	}
	var wg sync.WaitGroup
	var err1, err2 error
	wg.Add(2)
	go func(e error) {
		err1 = transport.Forward(tunnelConn, conn)
		wg.Done()
	}(err1)
	go func(e error) {
		err2 = transport.Forward(conn, tunnelConn)
		wg.Done()
	}(err2)
	wg.Wait()
	if err1 != nil {
		return util.ErrWrapper(err1, "error occurred when tunneling client request to client")
	}
	if err2 != nil {
		return util.ErrWrapper(err2, "error occurred when tunneling client response to client")
	}
	return nil
}

//proxy the https connetions by MITM
func (h *Handler) decryptConnect(c net.Conn, hostWithPort string,
	bufioPool *bufiopool.Pool, sniffer Sniffer, client *client.Client) error {
	//fakeTargetServer means a fake target server for remote client
	//make a connection with client by creating a fake target server
	//
	//make a fake target server's certificate
	fakeTargetServerCert, err := h.signFakeCert(h.MitmCACert, hostWithPort)
	if err != nil {
		h.sendHTTPSProxyStatusBadGateway(c)
		return util.ErrWrapper(err, "fail to sign fake certificate for client")
	}
	//make the target server's config with this fake certificate
	targetServerName := ""
	fakeTargetServerTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{*fakeTargetServerCert},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			targetServerName = hello.ServerName
			return cert.GenCert(h.MitmCACert, []string{hello.ServerName})
		},
	}
	//perform the proxy hand shake and fake tls handshake
	handShake := func() (*tls.Conn, error) {
		//make the proxy handshake
		if err := h.sendHTTPSProxyStatusOK(c); err != nil {
			return nil, util.ErrWrapper(err, "proxy fails to handshake with client")
		}
		//make the tls handshake in https
		conn := tls.Server(c, fakeTargetServerTLSConfig)
		if err := conn.Handshake(); err != nil {
			conn.Close()
			return nil, util.ErrWrapper(err, "fake tls server fails to handshake with client")
		}
		return conn, nil
	}
	fakeServerConn, err := handShake()
	if len(targetServerName) == 0 {
		err = errors.New("client didn't provide a target server name")
	}
	if err != nil {
		return err
	}
	defer fakeServerConn.Close()

	//make a connection with target server by creating a fake remote client
	//
	//convert fakeServerConn into a http request
	reader := bufioPool.AcquireReader(fakeServerConn)
	defer bufioPool.ReleaseReader(reader)
	req := AcquireRequest()
	defer ReleaseRequest(req)
	if err := req.InitWithTLSClientReader(reader,
		sniffer, targetServerName); err != nil {
		return util.ErrWrapper(err, "fail to read fake tls server request header")
	}
	//mandatory for tls request cause non hosts provided in request header
	req.SetHostWithPort(hostWithPort)
	//set requests proxy
	req.SetProxy(h.URLProxy(hostWithPort, req.reqLine.Path()))

	//convert fakeServerConn into a http response
	writer := bufioPool.AcquireWriter(fakeServerConn)
	defer bufioPool.ReleaseWriter(writer)
	defer writer.Flush()
	resp := AcquireResponse()
	defer ReleaseResponse(resp)
	if err := resp.InitWithWriter(writer, sniffer); err != nil {
		return util.ErrWrapper(err, "fail to int fake tls client")
	}
	//handle fake https client request
	if e := client.Do(req, resp); e != nil {
		return util.ErrWrapper(e, "fail to make fake tls client request")
	}
	return nil
}

func (h *Handler) signFakeCert(mitmCACert *tls.Certificate, host string) (*tls.Certificate, error) {
	domain, _, err := net.SplitHostPort(host)
	if err != nil {
		return nil, err
	}
	cert, err2 := cert.GenCert(mitmCACert, []string{domain})
	if err2 != nil {
		return nil, err2
	}
	return cert, nil
}
