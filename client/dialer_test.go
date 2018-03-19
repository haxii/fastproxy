package client

import (
	"bufio"
	"testing"

	"github.com/haxii/fastproxy/superproxy"
)

// test parse request type
func TestParseRequestType(t *testing.T) {
	vRequest := &VariedRequest{}
	vRequest.SetProxy(nil)
	vRequest.SetIsTLS(false)
	reqType := parseRequestType(vRequest)
	if reqType != requestDirectHTTP {
		t.Fatal("reqType should be requestDirectHTTP")
	}

	vRequest.SetIsTLS(true)
	reqType = parseRequestType(vRequest)
	if reqType != requestDirectHTTPS {
		t.Fatal("reqType should be requestDirectHTTPS")
	}

	vRequest.SetIsTLS(false)
	s, _ := superproxy.NewSuperProxy("0.0.0.0", 8080, superproxy.ProxyTypeHTTP, "", "", "")
	vRequest.SetProxy(s)
	reqType = parseRequestType(vRequest)
	if reqType != requestProxyHTTP {
		t.Fatal("reqType should be fallthrough")
	}

	s, _ = superproxy.NewSuperProxy("0.0.0.0", 8081, superproxy.ProxyTypeSOCKS5, "", "", "")
	vRequest.SetProxy(s)
	reqType = parseRequestType(vRequest)
	if reqType != requestProxySOCKS5 {
		t.Fatal("reqType should be requestProxySOCKS5")
	}

	s, _ = superproxy.NewSuperProxy("0.0.0.0", 8082, superproxy.ProxyTypeHTTPS, "", "", "")
	vRequest.SetProxy(s)
	reqType = parseRequestType(vRequest)
	if reqType != requestProxyHTTP {
		t.Fatal("reqType should be requestProxyHTTP")
	}

	s, _ = superproxy.NewSuperProxy("0.0.0.0", 8083, superproxy.ProxyTypeHTTPS, "", "", "")
	vRequest.SetProxy(s)
	vRequest.SetIsTLS(true)
	reqType = parseRequestType(vRequest)
	if reqType != requestProxyHTTPS {
		t.Fatal("reqType should be requestProxyHTTPS")
	}
}

type VariedRequest struct {
	superProxy *superproxy.SuperProxy
	isTLS      bool
}

func (r *VariedRequest) Method() []byte {
	return []byte("GET")
}

func (r *VariedRequest) TargetWithPort() string {
	return "127.0.0.1"
}
func (r *VariedRequest) SetTargetWithPort(s string) {}

func (r *VariedRequest) PathWithQueryFragment() []byte {
	return []byte("/https")
}

func (r *VariedRequest) Protocol() []byte {
	return []byte("HTTP/1.1")
}

func (r *VariedRequest) WriteHeaderTo(w *bufio.Writer) (int, int, error) {
	header := "Host: www.bing.com\r\nUser-Agent: test client\r\n" + "\r\n"
	n, err := w.WriteString(header)
	return len(header), n, err
}

func (r *VariedRequest) WriteBodyTo(w *bufio.Writer) (int, error) {
	return 0, nil
}

func (r *VariedRequest) ConnectionClose() bool {
	return false
}

func (r *VariedRequest) IsTLS() bool {
	return r.isTLS
}

func (r *VariedRequest) SetIsTLS(b bool) {
	r.isTLS = b
}

func (r *VariedRequest) TLSServerName() string {
	return ""
}

func (r *VariedRequest) GetProxy() *superproxy.SuperProxy {
	return r.superProxy
}

func (r *VariedRequest) SetProxy(s *superproxy.SuperProxy) {
	r.superProxy = s
}
