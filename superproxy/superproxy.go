package superproxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/transport"
)

// ProxyType type of super proxy
type ProxyType int

const (
	// ProxyTypeHTTP a traditional http proxy
	ProxyTypeHTTP ProxyType = iota
	// ProxyTypeHTTPS a HTTPS proxy a.k.a. which supports SSL
	ProxyTypeHTTPS
	// ProxyTypeSOCKS5 a SOCKS5 proxy
	ProxyTypeSOCKS5
)

//SuperProxy chaining proxy
type SuperProxy struct {
	host              string
	port              int
	hostWithPort      string
	hostWithPortBytes []byte

	// proxyType, HTTP/HTTPS/SOCKS5
	proxyType ProxyType
	// proxy net connections pool/manager
	connManager transport.ConnManager

	// whether the super proxy supports SSL encryption?
	// if so, tlsConfig is set using host
	tlsConfig *tls.Config

	// HTTP proxy auth header
	authHeaderWithCRLF []byte

	// SOCKS5 greetings & auth header
	socks5Greetings []byte
	socks5Auth      []byte
}

// NewSuperProxy new a super proxy
func NewSuperProxy(host string, port uint16, proxyType ProxyType,
	user string, pass string) (*SuperProxy, error) {
	// check input vars
	if len(host) == 0 {
		return nil, errors.New("nil host provided")
	}
	if port == 0 {
		return nil, errors.New("nil port provided")
	}

	// make a super proxy instance
	s := &SuperProxy{
		host:      host,
		port:      int(port),
		proxyType: proxyType,
		connManager: transport.ConnManager{
			MaxConns:            1024,
			MaxIdleConnDuration: 10 * time.Second,
		},
	}
	s.hostWithPort = fmt.Sprintf("%s:%d", host, port)
	s.hostWithPortBytes = make([]byte, len(s.hostWithPort))
	copy(s.hostWithPortBytes, []byte(s.hostWithPort))

	if proxyType != ProxyTypeSOCKS5 {
		s.initHTTPCertAndAuth(proxyType == ProxyTypeHTTPS, host, user, pass)
	} else {
		s.initSOCKS5GreetingsAndAuth(host, user, pass)
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

// HTTPProxyAuthHeaderWithCRLF HTTP proxy basic auth header with CRLF if user & password is set
func (p *SuperProxy) HTTPProxyAuthHeaderWithCRLF() []byte {
	return p.authHeaderWithCRLF
}

// MakeTunnel makes a TCP tunnel by making a connect request to proxy
func (p *SuperProxy) MakeTunnel(pool *bufiopool.Pool,
	hostWithPort string) (net.Conn, error) {
	var (
		c   net.Conn
		err error
	)
	switch p.proxyType {
	case ProxyTypeHTTP:
		c, err = transport.Dial(p.hostWithPort)
	case ProxyTypeHTTPS:
		c, err = transport.DialTLS(p.hostWithPort, p.tlsConfig)
	case ProxyTypeSOCKS5:
	}

	if err != nil {
		return nil, err
	}

	if p.proxyType != ProxyTypeSOCKS5 {
		// HTTP/HTTPS tunnel establishing
		if err := p.writeHTTPProxyReq(c, []byte(hostWithPort)); err != nil {
			c.Close()
			return nil, err
		}
		if err = p.readHTTPProxyResp(c, pool); err != nil {
			c.Close()
			return nil, err
		}
	} else {
		// SOCKS5 tunnel establishing
		if err = p.connectSOCKS5Proxy(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}
