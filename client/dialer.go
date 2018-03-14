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

func (r *requestType) Value() int {
	return int(*r)
}

func parseRequestType(req Request) requestType {
	superProxy := req.GetProxy()
	isHTTPS := req.IsTLS()
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

func (c *HostClient) makeDialer(req Request) transport.Dialer {
	reqType := parseRequestType(req)
	//set https tls config
	switch reqType {
	case requestDirectHTTP:
		return dialerWrapper(transport.Dial(req.TargetWithPort()))
	case requestDirectHTTPS:
		if c.tlsServerConfig == nil {
			c.tlsServerConfig = cert.MakeClientTLSConfig(req.TargetWithPort(), req.TLSServerName())
		}
		return dialerWrapper(transport.DialTLS(req.TargetWithPort(), c.tlsServerConfig))
	case requestProxyHTTP:
		return dialerWrapper(transport.Dial(req.GetProxy().HostWithPort()))
	case requestProxyHTTPS:
		if c.tlsServerConfig == nil {
			c.tlsServerConfig = &tls.Config{
				ClientSessionCache: tls.NewLRUClientSessionCache(0),
				InsecureSkipVerify: true, //TODO: cache every host config in more safe way in a concurrent map
			}
		}
		fallthrough
	case requestProxySOCKS5:
		tunnelConn, err := req.GetProxy().MakeTunnel(c.BufioPool, req.TargetWithPort())
		if err != nil {
			return dialerWrapper(nil, err)
		}
		if reqType == requestProxyHTTPS {
			conn := tls.Client(tunnelConn, c.tlsServerConfig)
			return dialerWrapper(conn, nil)
		}
		return dialerWrapper(tunnelConn, nil)
	}
	return dialerWrapper(nil, errors.New("request type not implemented"))
}

// wrap a connection and error into a tranport Dialer
func dialerWrapper(c net.Conn, e error) transport.Dialer {
	return func() (net.Conn, error) {
		return c, e
	}
}
