package client

import (
	"crypto/tls"
	"errors"
	"net"

	"github.com/haxii/fastproxy/cert"
	"github.com/haxii/fastproxy/superproxy"
	"github.com/haxii/fastproxy/transport"
)

type requestType int

const (
	requestDirectHTTP requestType = iota
	requestDirectHTTPS
	requestProxyHTTP
	requestProxyHTTPS
	requestProxySOCKS5
)

func (r requestType) isTLS() bool {
	return (r == requestDirectHTTPS) || (r == requestProxyHTTPS)
}

func parseRequestType(superProxy *superproxy.SuperProxy, isHTTPS bool) requestType {
	var rt requestType
	if superProxy == nil {
		if !isHTTPS {
			rt = requestDirectHTTP
		} else {
			rt = requestDirectHTTPS
		}
	} else {
		switch superProxy.GetProxyType() {
		case superproxy.ProxyTypeSOCKS5:
			rt = requestProxySOCKS5
		case superproxy.ProxyTypeHTTP:
			fallthrough
		case superproxy.ProxyTypeHTTPS:
			if !isHTTPS {
				rt = requestProxyHTTP
			} else {
				rt = requestProxyHTTPS
			}
		}
	}
	return rt
}

func (c *HostClient) makeDialer(superProxy *superproxy.SuperProxy,
	targetWithPort string, isTargetHTTPS bool, targetTLSServerName string) transport.NewConn {
	reqType := parseRequestType(superProxy, isTargetHTTPS)
	// setup dial functions
	dialFunc := c.Dial
	if dialFunc == nil {
		dialFunc = transport.Dial
	}
	dialTLSFunc := c.DialTLS
	if dialTLSFunc == nil {
		dialTLSFunc = transport.DialTLS
	}
	//set https tls config
	switch reqType {
	case requestDirectHTTP:
		return dialerWrapper(dialFunc(targetWithPort))
	case requestDirectHTTPS:
		if c.tlsServerConfig == nil {
			c.tlsServerConfig = cert.MakeClientTLSConfig("", targetTLSServerName)
		}
		return dialerWrapper(dialTLSFunc(targetWithPort, c.tlsServerConfig))
	case requestProxyHTTP:
		return dialerWrapper(dialFunc(superProxy.HostWithPort()))
	case requestProxyHTTPS:
		fallthrough
	case requestProxySOCKS5:
		tunnelConn, err := superProxy.MakeTunnel(c.Dial, c.DialTLS, c.BufioPool, targetWithPort)
		if err != nil {
			return dialerWrapper(nil, err)
		}
		if isTargetHTTPS {
			if c.tlsServerConfig == nil {
				c.tlsServerConfig = &tls.Config{
					ClientSessionCache: tls.NewLRUClientSessionCache(0),
					InsecureSkipVerify: true, //TODO: cache every host config in more safe way in a concurrent map
				}
			}
			conn := tls.Client(tunnelConn, c.tlsServerConfig)
			return dialerWrapper(conn, nil)
		}
		return dialerWrapper(tunnelConn, nil)
	}
	return dialerWrapper(nil, errors.New("request type not implemented"))
}

// wrap a connection and error into a transport Dialer
func dialerWrapper(c net.Conn, e error) transport.NewConn {
	return func() (net.Conn, error) {
		return c, e
	}
}
