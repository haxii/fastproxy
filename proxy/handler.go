package proxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/haxii/fastproxy/cert"
	"github.com/haxii/fastproxy/log"
	"github.com/haxii/fastproxy/transport"
)

//handler proxy http & https handler
type handler struct {
	// CA specifies the root CA for generating leaf certs for each incoming
	// TLS request.
	CA *tls.Certificate

	//handler's logger
	logger log.Logger
}

func (h *handler) sendHTTPSProxyStatusOK(c net.Conn) (err error) {
	_, err = c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	return
}

func (h *handler) sendHTTPSProxyStatusBadGateway(c net.Conn) (err error) {
	_, err = c.Write([]byte("HTTP/1.1 501 Bad Gateway\r\n\r\n"))
	return
}

//proxy https traffic directly
func (h *handler) forwardConnect(c *net.Conn, host string) {
	//acquire server conn to target host
	var targetConn *net.Conn
	if _targetConn, err := transport.Dial(host); err == nil {
		targetConn = &_targetConn
	} else {
		h.logger.Error(err, "error occurred when dialing to host %s", host)
		h.sendHTTPSProxyStatusBadGateway(*c)
		return
	}
	defer (*targetConn).Close()

	//handshake with client
	if err := h.sendHTTPSProxyStatusOK(*c); err != nil {
		h.logger.Error(err, "error occurred when handshaking with client")
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go transport.Forward(*targetConn, *c, h.logger, &wg)
	go transport.Forward(*c, *targetConn, h.logger, &wg)
	wg.Wait()
}

//proxy the https connetions by MITM
func (h *handler) decryptConnect(c net.Conn, host string) {
	//fakeRemoteClient means a fake remote client
	//fakeTargetServer means a fake target server for remote client

	//make a connection with client by creating a fake target server
	//
	//make a fake target server's certificate
	fakeTargetServerCert, err := h.signFakeCert(host)
	if err != nil {
		h.logger.Error(err, "error occurred when signing fake certificate for client")
		h.sendHTTPSProxyStatusBadGateway(c)
		return
	}
	//make the target server's config with this fake certificate
	targetServerName := ""
	fakeTargetServerTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{*fakeTargetServerCert},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			targetServerName = hello.ServerName
			return cert.GenCert(h.CA, []string{hello.ServerName})
		},
	}
	//perform the proxy hand shake and fake tls handshake
	handShake := func() (*tls.Conn, error) {
		//make the proxy handshake
		if err := h.sendHTTPSProxyStatusOK(c); err != nil {
			return nil, fmt.Errorf("proxy handshaking error: %s", err)
		}
		//make the tls handshake in https
		conn := tls.Server(c, fakeTargetServerTLSConfig)
		if err := conn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("fake server tls handshaking error: %s", err)
		}
		return conn, nil
	}
	fakeServerConn, err := handShake()
	if len(targetServerName) == 0 {
		err = errors.New("client didn't provide a target server name")
	}
	if err != nil {
		h.logger.Error(err, "error occurred when handshaking with client")
		//TODO: set error message
		return
	}
	defer fakeServerConn.Close()

	//make a connection with target server by creating a fake remote client
	//
	//make a fake client tls config
	fakeRemoteClientTLSConfig := &tls.Config{
		ServerName: targetServerName,
	}
	//make the client tls connection

	_fakeRemoteClientConn, err := transport.Dial(host)
	if err != nil {
		h.logger.Error(err, "error occurred when dialing tls to host %s", host)
		return
	}
	fakeRemoteClientConn := tls.Client(_fakeRemoteClientConn, fakeRemoteClientTLSConfig)
	defer fakeRemoteClientConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go transport.Forward(fakeServerConn, fakeRemoteClientConn, h.logger, &wg)
	go transport.Forward(fakeRemoteClientConn, fakeServerConn, h.logger, &wg)
	wg.Wait()
	return
}

func (h *handler) signFakeCert(host string) (*tls.Certificate, error) {
	domain, _, err := net.SplitHostPort(host)
	if err != nil {
		return nil, fmt.Errorf("get host's %s domain with error %s", host, err)
	}
	cert, err2 := cert.GenCert(h.CA, []string{domain})
	if err2 != nil {
		return nil, fmt.Errorf("sign %s fake cert with error %s", domain, err2)
	}
	return cert, nil
}
