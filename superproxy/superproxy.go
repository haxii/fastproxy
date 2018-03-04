package superproxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/transport"
	"github.com/haxii/fastproxy/usage"
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

	//usage
	Usage *usage.ProxyUsage
}

// NewSuperProxy new a super proxy
func NewSuperProxy(proxyHost string, proxyPort uint16, proxyType ProxyType,
	user string, pass string, shouldOpenUsage bool) (*SuperProxy, error) {
	// check input vars
	if len(proxyHost) == 0 {
		return nil, errors.New("nil host provided")
	}
	if proxyPort == 0 {
		return nil, errors.New("nil port provided")
	}

	// make a super proxy instance
	s := &SuperProxy{
		proxyType: proxyType,
		connManager: transport.ConnManager{
			MaxConns:            1024,
			MaxIdleConnDuration: 10 * time.Second,
		},
	}
	s.hostWithPort = fmt.Sprintf("%s:%d", proxyHost, proxyPort)
	s.hostWithPortBytes = make([]byte, len(s.hostWithPort))
	copy(s.hostWithPortBytes, []byte(s.hostWithPort))

	if proxyType != ProxyTypeSOCKS5 {
		s.initHTTPCertAndAuth(proxyType == ProxyTypeHTTPS, proxyHost, user, pass)
	} else {
		s.initSOCKS5GreetingsAndAuth(user, pass)
	}

	if shouldOpenUsage {
		s.Usage = &usage.ProxyUsage{}
		s.Usage.Start()
	}

	return s, nil
}

//GetProxyType returns super proxy type
func (p *SuperProxy) GetProxyType() ProxyType {
	return p.proxyType
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
	targetHostWithPort string) (net.Conn, error) {
	var (
		c   net.Conn
		err error
	)
	switch p.proxyType {
	case ProxyTypeHTTP:
		fallthrough
	case ProxyTypeSOCKS5:
		c, err = transport.Dial(p.hostWithPort)
	case ProxyTypeHTTPS:
		c, err = transport.DialTLS(p.hostWithPort, p.tlsConfig)
	}

	if err != nil {
		return nil, err
	}

	if p.proxyType != ProxyTypeSOCKS5 {
		// HTTP/HTTPS tunnel establishing
		if err := p.writeHTTPProxyReq(c, []byte(targetHostWithPort)); err != nil {
			c.Close()
			return nil, err
		}
		if err = p.readHTTPProxyResp(c, pool); err != nil {
			c.Close()
			return nil, err
		}
	} else {
		// SOCKS5 tunnel establishing
		targetHost, targetPortStr, err := net.SplitHostPort(targetHostWithPort)
		if err != nil {
			return nil, err
		}
		targetPort, err := strconv.Atoi(targetPortStr)
		if err != nil {
			return nil, errors.New("proxy: failed to parse target port number: " + targetPortStr)
		}
		if targetPort < 1 || targetPort > 0xffff {
			return nil, errors.New("proxy: target port number out of range: " + targetPortStr)
		}
		if err = p.connectSOCKS5Proxy(c, targetHost, targetPort); err != nil {
			return nil, err
		}
	}
	return c, nil
}
