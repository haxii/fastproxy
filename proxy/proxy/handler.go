package proxy

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/cert"
	"github.com/haxii/fastproxy/client"
	"github.com/haxii/fastproxy/hijack"
	"github.com/haxii/fastproxy/proxy/http"
	"github.com/haxii/fastproxy/superproxy"
	"github.com/haxii/fastproxy/transport"
	"github.com/haxii/fastproxy/usage"
	"github.com/haxii/fastproxy/util"
)

//Handler proxy handler
type Handler struct {
	//ShouldAllowConnection should allow the connection to proxy, return false to drop the conn
	ShouldAllowConnection func(connAddr net.Addr) bool

	//HTTPSDecryptEnable test if host's https connection should be decrypted
	ShouldDecryptHost func(host string) bool

	//URLProxy url specified proxy, nil path means this is a un-decrypted https traffic
	URLProxy func(hostWithPort string, path []byte) *superproxy.SuperProxy

	//hijacker pool for making a hijacker for every incoming request
	HijackerPool hijack.HijackerPool
	//hijacker client for make hijacked response if available
	hijackClient hijack.Client
	//MitmCACert HTTPSDecryptCACert ca.cer used for https decryption
	MitmCACert *tls.Certificate

	//http requests and response pool
	reqPool  http.RequestPool
	respPool http.ResponsePool
}

func (h *Handler) handleHTTPConns(c net.Conn, req *http.Request,
	bufioPool *bufiopool.Pool, client *client.Client, usage *usage.ProxyUsage) error {
	return h.do(c, req, bufioPool, client, usage)
}

func (h *Handler) do(c net.Conn, req *http.Request,
	bufioPool *bufiopool.Pool, client *client.Client, usage *usage.ProxyUsage) error {
	//convert connetion into a http response
	writer := bufioPool.AcquireWriter(c)
	defer bufioPool.ReleaseWriter(writer)
	defer writer.Flush()
	resp := h.respPool.Acquire()
	defer h.respPool.Release(resp)
	if err := resp.WriteTo(writer); err != nil {
		return err
	}

	//set requests hijacker
	hijacker := h.HijackerPool.Get(c.RemoteAddr(),
		req.HostWithPort(), req.Method(), req.PathWithQueryFragment())
	defer h.HijackerPool.Put(hijacker)

	//set request & response hijacker
	req.SetHijacker(hijacker)
	resp.SetHijacker(hijacker)
	if hijackedRespReader := hijacker.HijackResponse(); hijackedRespReader != nil {
		err := h.hijackClient.Do(req, resp, hijackedRespReader)
		if usage != nil {
			usage.AddIncomingSize(uint64(req.GetReadSize()))
			usage.AddOutgoingSize(uint64(resp.GetSize()))
		}
		return err
	}

	//set requests proxy
	superProxy := h.URLProxy(req.HostWithPort(), req.PathWithQueryFragment())
	req.SetProxy(superProxy)
	if superProxy != nil {
		superProxy.AcquireToken()
		defer func() {
			superProxy.PushBackToken()
		}()
	}

	//handle http proxy request
	err := client.Do(req, resp)
	if usage != nil {
		usage.AddIncomingSize(uint64(req.GetReadSize()))
		usage.AddOutgoingSize(uint64(resp.GetSize()))
	}
	if superProxy != nil && superProxy.Usage != nil {
		superProxy.Usage.AddIncomingSize(uint64(resp.GetSize()))
		superProxy.Usage.AddOutgoingSize(uint64(req.GetWriteSize()))
	}

	return err
}

func (h *Handler) handleHTTPSConns(c net.Conn, hostWithPort string,
	bufioPool *bufiopool.Pool, client *client.Client, usage *usage.ProxyUsage) error {
	if h.ShouldDecryptHost(hostWithPort) {
		return h.decryptConnect(c, hostWithPort, bufioPool, client, usage)
	}
	return h.tunnelConnect(c, bufioPool, hostWithPort, usage)
}

func (h *Handler) sendHTTPSProxyStatusOK(c net.Conn) (err error) {
	return util.WriteWithValidation(c, []byte("HTTP/1.1 200 OK\r\n\r\n"))
}

func (h *Handler) sendHTTPSProxyStatusBadGateway(c net.Conn) (err error) {
	return util.WriteWithValidation(c, []byte("HTTP/1.1 501 Bad Gateway\r\n\r\n"))
}

var (
	HttpOkByteSize         = uint64(len([]byte("HTTP/1.1 200 OK\r\n\r\n")))
	HttpBadGatewayByteSize = uint64(len([]byte("HTTP/1.1 501 Bad Gateway\r\n\r\n")))
)

//proxy https traffic directly
func (h *Handler) tunnelConnect(conn net.Conn,
	bufioPool *bufiopool.Pool, hostWithPort string, usage *usage.ProxyUsage) error {
	superProxy := h.URLProxy(hostWithPort, nil)
	if superProxy != nil {
		superProxy.AcquireToken()
		defer func() {
			superProxy.PushBackToken()
		}()
	}

	var (
		tunnelConn net.Conn
		err        error
	)
	if superProxy != nil {
		//acquire server conn to target host
		tunnelConn, err = superProxy.MakeTunnel(bufioPool, hostWithPort)
	} else {
		//acquire server conn to target host
		tunnelConn, err = transport.Dial(hostWithPort)
	}

	if err != nil {
		h.sendHTTPSProxyStatusBadGateway(conn)
		if usage != nil {
			usage.AddOutgoingSize(HttpBadGatewayByteSize)
		}
		return util.ErrWrapper(err, "error occurred when dialing to host "+hostWithPort)
	}
	defer tunnelConn.Close()

	//handshake with client
	if err := h.sendHTTPSProxyStatusOK(conn); err != nil {
		return util.ErrWrapper(err, "error occurred when handshaking with client")
	}
	if usage != nil {
		usage.AddOutgoingSize(HttpOkByteSize)
	}

	var wg sync.WaitGroup
	var superProxyWriteErr, superProxyReadErr error
	var superProxyOutgoingTrafficSize, superProxyIncomingTrafficSize int64
	wg.Add(2)
	go func() {
		superProxyOutgoingTrafficSize, superProxyWriteErr = transport.Forward(tunnelConn, conn)
		wg.Done()
	}()
	go func() {
		superProxyIncomingTrafficSize, superProxyReadErr = transport.Forward(conn, tunnelConn)
		wg.Done()
	}()
	wg.Wait()

	if superProxyOutgoingTrafficSize > 0 {
		if usage != nil {
			usage.AddIncomingSize(uint64(superProxyOutgoingTrafficSize))
		}
		if superProxy != nil && superProxy.Usage != nil {
			superProxy.Usage.AddOutgoingSize(uint64(superProxyOutgoingTrafficSize))
		}
	}
	if superProxyIncomingTrafficSize > 0 {
		if usage != nil {
			usage.AddOutgoingSize(uint64(superProxyIncomingTrafficSize))
		}
		if superProxy != nil && superProxy.Usage != nil {
			superProxy.Usage.AddIncomingSize(uint64(superProxyIncomingTrafficSize))
		}
	}

	if superProxyWriteErr != nil {
		return util.ErrWrapper(superProxyWriteErr, "error occurred when tunneling client request to client")
	}
	if superProxyReadErr != nil {
		return util.ErrWrapper(superProxyReadErr, "error occurred when tunneling client response to client")
	}
	return nil
}

//proxy the https connetions by MITM
func (h *Handler) decryptConnect(c net.Conn, hostWithPort string,
	bufioPool *bufiopool.Pool, client *client.Client, usage *usage.ProxyUsage) error {
	//fakeTargetServer means a fake target server for remote client
	//make a connection with client by creating a fake target server
	//
	//make a fake target server's certificate
	fakeTargetServerCert, err := h.signFakeCert(h.MitmCACert, hostWithPort)
	if err != nil {
		h.sendHTTPSProxyStatusBadGateway(c)
		if usage != nil {
			usage.AddOutgoingSize(HttpBadGatewayByteSize)
		}
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
		if usage != nil {
			usage.AddOutgoingSize(HttpOkByteSize)
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
	req := h.reqPool.Acquire()
	defer h.reqPool.Release(req)
	if err := req.ReadFrom(reader); err != nil {
		return util.ErrWrapper(err, "fail to read fake tls server request header")
	}
	req.SetTLS(targetServerName)
	//mandatory for tls request cause non hosts provided in request header
	req.SetHostWithPort(hostWithPort)

	return h.do(fakeServerConn, req, bufioPool, client, usage)
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
