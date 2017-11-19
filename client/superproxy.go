package client

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/bytebufferpool"
	"github.com/haxii/fastproxy/transport"
	"github.com/haxii/fastproxy/util"
)

//SuperProxy chaining proxy
type SuperProxy struct {
	hostWithPort       string
	hostWithPortBytes  []byte
	authHeaderWithCRLF []byte
	secure             bool
	tlsConfig          *tls.Config
}

//NewSuperProxy new a super proxy
func NewSuperProxy(host string, port uint16, ssl bool,
	user string, pass string) (*SuperProxy, error) {
	basicAuth := func(username, password string) string {
		auth := username + ":" + password
		return base64.StdEncoding.EncodeToString([]byte(auth))
	}
	if len(host) == 0 {
		return nil, errors.New("nil host provided")
	}
	if port == 0 {
		return nil, errors.New("nil port provided")
	}
	s := &SuperProxy{secure: ssl}
	if ssl {
		s.tlsConfig = newClientTLSConfig(host, "")
	}
	s.hostWithPort = fmt.Sprintf("%s:%d", host, port)
	s.hostWithPortBytes = make([]byte, len(s.hostWithPort))
	copy(s.hostWithPortBytes, []byte(s.hostWithPort))
	if len(user) > 0 && len(pass) > 0 {
		authHeaderWithCRLFStr := "Proxy-Authorization: Basic " + basicAuth(user, pass) + "\r\n"
		s.authHeaderWithCRLF = make([]byte, len(authHeaderWithCRLFStr))
		copy(s.authHeaderWithCRLF, []byte(authHeaderWithCRLFStr))
	} else {
		s.authHeaderWithCRLF = nil
	}
	return s, nil
}

//DialFunc return a dial func using super proxy
func (p *SuperProxy) DialFunc(pool *bufiopool.Pool) transport.DialFunc {
	return func(hostWithPort string) (net.Conn, error) {
		var (
			c   net.Conn
			err error
		)
		if p.secure {
			c, err = transport.Dial(p.hostWithPort)
		} else {
			c, err = transport.DialTLS(p.hostWithPort, p.tlsConfig)
		}
		if err != nil {
			return nil, err
		}

		if err := p.writeProxyReq(c, []byte(hostWithPort)); err != nil {
			c.Close()
			return nil, err
		}
		if err = p.readProxyReq(c, pool); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}
}

var (
	superProxyReqMethod     = []byte("CONNECT")
	superProxyReqProtocol   = []byte("HTTP/1.1")
	superProxyReqHostHeader = []byte("Host:")
	superProxyReqSP         = []byte(" ")
	lensuperProxyReqSP      = 1
	superProxyReqCRLF       = []byte("\r\n")
	lensuperProxyReqCRLF    = 2
)

//writeProxyReq write proxy `CONNECT` header to proxy connection,
//as shown blow:
// CONNECT targetHost:Port HTTP/1.1\r\n
// Host: targetHost:Port\r\n
// * proxy auth if needed *
// \r\n
func (p *SuperProxy) writeProxyReq(c net.Conn, targetHostWithPort []byte) error {
	buf := bytebufferpool.Get()
	defer bytebufferpool.Put(buf)
	buf.B = make([]byte, len(superProxyReqMethod)+lensuperProxyReqSP+
		len(targetHostWithPort)+lensuperProxyReqSP+
		len(superProxyReqProtocol)+lensuperProxyReqCRLF+
		len(superProxyReqHostHeader)+lensuperProxyReqSP+
		len(targetHostWithPort)+lensuperProxyReqCRLF+
		len(p.authHeaderWithCRLF)+lensuperProxyReqCRLF)

	copyIndex := 0
	copyBytes := func(b []byte) {
		copy(buf.B[copyIndex:], b)
		copyIndex += len(b)
	}
	copySuperProxyReqSP := func() {
		copy(buf.B[copyIndex:], superProxyReqSP)
		copyIndex += lensuperProxyReqSP
	}
	copySuperProxyReqCRLF := func() {
		copy(buf.B[copyIndex:], superProxyReqCRLF)
		copyIndex += lensuperProxyReqCRLF
	}
	copyBytes(superProxyReqMethod)
	copySuperProxyReqSP()
	copyBytes(targetHostWithPort)
	copySuperProxyReqSP()
	copyBytes(superProxyReqProtocol)
	copySuperProxyReqCRLF()
	copyBytes(superProxyReqHostHeader)
	copySuperProxyReqSP()
	copyBytes(targetHostWithPort)
	copySuperProxyReqCRLF()
	copyBytes(p.authHeaderWithCRLF)
	copySuperProxyReqCRLF()
	return util.WriteWithValidation(c, buf.B)
}

//readProxyReq reads proxy connection request result (i.e. response)
//only 200 OK is accepted.
func (p *SuperProxy) readProxyReq(c net.Conn, pool *bufiopool.Pool) error {
	r := pool.AcquireReader(c)
	defer pool.ReleaseReader(r)

	return nil
}
