package superproxy

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/bytebufferpool"
	"github.com/haxii/fastproxy/cert"
	"github.com/haxii/fastproxy/transport"
	"github.com/haxii/fastproxy/util"
)

//SuperProxy chaining proxy
type SuperProxy struct {
	hostWithPort       string
	hostWithPortBytes  []byte
	authHeaderWithCRLF []byte

	// whether the super proxy supports ssl encryption
	// if so, tlsConfig is set using host
	secure    bool
	tlsConfig *tls.Config

	// proxy net connections pool/manager
	connManager transport.ConnManager
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
	s := &SuperProxy{
		secure: ssl,
		connManager: transport.ConnManager{
			MaxConns:            1024,
			MaxIdleConnDuration: 10 * time.Second,
		},
	}
	if ssl {
		s.tlsConfig = cert.MakeClientTLSConfig(host, "")
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

// HostWithPort host with port in string
// refer to `HostWithPortBytes` if you need a byte slice version
func (p *SuperProxy) HostWithPort() string {
	return p.hostWithPort
}

// HostWithPortBytes host with port in bytes
// refer to `HostWithPort` if you need a string version
func (p *SuperProxy) HostWithPortBytes() []byte {
	return p.hostWithPortBytes

}

// AuthHeaderWithCRLF basic auth header with CRLF if user & password is set
func (p *SuperProxy) AuthHeaderWithCRLF() []byte {
	return p.authHeaderWithCRLF
}

//MakeHTTPTunnel make a http tunnel by making a connect request to proxy
func (p *SuperProxy) MakeHTTPTunnel(pool *bufiopool.Pool,
	hostWithPort string) (net.Conn, error) {
	var (
		c   net.Conn
		err error
	)
	if p.secure {
		c, err = transport.DialTLS(p.hostWithPort, p.tlsConfig)
	} else {
		c, err = transport.Dial(p.hostWithPort)
	}
	if err != nil {
		return nil, err
	}

	if err := p.writeProxyReq(c, []byte(hostWithPort)); err != nil {
		c.Close()
		return nil, err
	}
	if err = p.readProxyResp(c, pool); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

var (
	superProxyReqMethod     = []byte("CONNECT")
	superProxyReqProtocol   = []byte("HTTP/1.1")
	superProxyReqHostHeader = []byte("Host:")
	superProxyReqSP         = []byte(" ")
	superProxyReqCRLF       = []byte("\r\n")
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
	buf.B = make([]byte, len(superProxyReqMethod)+len(superProxyReqSP)+
		len(targetHostWithPort)+len(superProxyReqSP)+
		len(superProxyReqProtocol)+len(superProxyReqCRLF)+
		len(superProxyReqHostHeader)+len(superProxyReqSP)+
		len(targetHostWithPort)+len(superProxyReqCRLF)+
		len(p.authHeaderWithCRLF)+len(superProxyReqCRLF))
	copyIndex := 0
	copyBytes := func(b []byte) {
		copy(buf.B[copyIndex:], b)
		copyIndex += len(b)
	}
	copyBytes(superProxyReqMethod)
	copyBytes(superProxyReqSP)
	copyBytes(targetHostWithPort)
	copyBytes(superProxyReqSP)
	copyBytes(superProxyReqProtocol)
	copyBytes(superProxyReqCRLF)
	copyBytes(superProxyReqHostHeader)
	copyBytes(superProxyReqSP)
	copyBytes(targetHostWithPort)
	copyBytes(superProxyReqCRLF)
	copyBytes(p.authHeaderWithCRLF)
	copyBytes(superProxyReqCRLF)
	return util.WriteWithValidation(c, buf.B)
}

//readProxyReq reads proxy connection request result (i.e. response)
//only 200 OK is accepted.
func (p *SuperProxy) readProxyResp(c net.Conn, pool *bufiopool.Pool) error {
	r := pool.AcquireReader(c)
	defer pool.ReleaseReader(r)
	n := 1
	isStartLine := true
	headerParsed := false
	for {
		if b, err := r.Peek(n); err != nil {
			return err
		} else if len(b) == 0 {
			return io.EOF
		}
		//must read buffed bytes
		b := util.PeekBuffered(r)
		//read and discard every header line
		m := 0
		for !headerParsed {
			b := b[m:]
			lineLen := bytes.IndexByte(b, '\n')
			if lineLen < 0 {
				//need more
				break
			}
			lineLen++
			m += lineLen
			if isStartLine {
				isStartLine = false
				if !bytes.Contains(b[:lineLen], []byte(" 200 ")) {
					return fmt.Errorf("connected to proxy failed with startline %s", b[:lineLen])
				}
			} else {
				if (lineLen == 2 && b[0] == '\r') || lineLen == 1 {
					//single \n or \r\n means end of the header
					headerParsed = true
				}
			}
			if _, err := r.Discard(lineLen); err != nil {
				return util.ErrWrapper(err, "fail to read proxy connect response")
			}
		}
		if headerParsed {
			//TODO: discard http body also? Does the proxy connect response contains body?
			return nil
		}
		//require one more byte
		n = r.Buffered() + 1
	}
}
