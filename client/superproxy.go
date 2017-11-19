package client

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
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
		if err = p.readProxyResp(c, pool); err != nil {
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
		b, err := r.Peek(r.Buffered())
		if len(b) == 0 || err != nil {
			return fmt.Errorf("bufio.Reader.Peek() returned unexpected data (%q, %v)", b, err)
		}
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
				return fmt.Errorf("bufio.Reader.Discard(%d) failed: %s", lineLen, err)
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
