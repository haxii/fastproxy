package superproxy

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/bytebufferpool"
	"github.com/haxii/fastproxy/cert"
	"github.com/haxii/fastproxy/util"
)

var (
	superProxyReqMethod     = []byte("CONNECT")
	superProxyReqProtocol   = []byte("HTTP/1.1")
	superProxyReqHostHeader = []byte("Host:")
	superProxyReqSP         = []byte(" ")
	superProxyReqCRLF       = []byte("\r\n")
)

func (p *SuperProxy) initHTTPCertAndAuth(isSSL bool, host string,
	user string, pass string) {
	// make HTTP/HTTPS proxy auth header
	basicAuth := func(username, password string) string {
		auth := username + ":" + password
		return base64.StdEncoding.EncodeToString([]byte(auth))
	}
	if isSSL {
		p.tlsConfig = cert.MakeClientTLSConfig(host, "")
	}
	if len(user) > 0 && len(pass) > 0 {
		authHeaderWithCRLFStr := "Proxy-Authorization: Basic " + basicAuth(user, pass) + "\r\n"
		p.authHeaderWithCRLF = make([]byte, len(authHeaderWithCRLFStr))
		copy(p.authHeaderWithCRLF, []byte(authHeaderWithCRLFStr))
	} else {
		p.authHeaderWithCRLF = nil
	}
}

//writeProxyReq write proxy `CONNECT` header to proxy connection,
//as shown blow:
// CONNECT targetHost:Port HTTP/1.1\r\n
// Host: targetHost:Port\r\n
// * proxy auth if needed *
// \r\n
func (p *SuperProxy) writeHTTPProxyReq(c net.Conn, targetHostWithPort []byte) error {
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
func (p *SuperProxy) readHTTPProxyResp(c net.Conn, pool *bufiopool.Pool) error {
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
