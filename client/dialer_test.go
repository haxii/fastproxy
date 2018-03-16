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
	s, _ := superproxy.NewSuperProxy("0.0.0.0", 8080, superproxy.ProxyTypeHTTP, "", "", false, "")
	vRequest.SetProxy(s)
	reqType = parseRequestType(vRequest)
	if reqType != requestProxyHTTP {
		t.Fatal("reqType should be fallthrough")
	}

	s, _ = superproxy.NewSuperProxy("0.0.0.0", 8081, superproxy.ProxyTypeSOCKS5, "", "", false, "")
	vRequest.SetProxy(s)
	reqType = parseRequestType(vRequest)
	if reqType != requestProxySOCKS5 {
		t.Fatal("reqType should be requestProxySOCKS5")
	}

	s, _ = superproxy.NewSuperProxy("0.0.0.0", 8082, superproxy.ProxyTypeHTTPS, "", "", false, "")
	vRequest.SetProxy(s)
	reqType = parseRequestType(vRequest)
	if reqType != requestProxyHTTP {
		t.Fatal("reqType should be requestProxyHTTP")
	}

	s, _ = superproxy.NewSuperProxy("0.0.0.0", 8083, superproxy.ProxyTypeHTTPS, "", "", false, "")
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

func (r *VariedRequest) WriteHeaderTo(w *bufio.Writer) error {
	_, err := w.WriteString("Host: www.bing.com\r\nUser-Agent: test client\r\n" + "\r\n")
	return err
}

func (r *VariedRequest) WriteBodyTo(w *bufio.Writer) error {
	return nil
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

func (r *VariedRequest) GetReadSize() int {
	return 0
}

func (r *VariedRequest) GetWriteSize() int {
	return 0
}

func (r *VariedRequest) AddReadSize(n int) {
}

func (r *VariedRequest) AddWriteSize(n int) {
}
