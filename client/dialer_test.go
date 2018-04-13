package client

import (
	"bufio"
	"testing"

	"github.com/balinor2017/fastproxy/superproxy"
)

// test parse request type
func TestParseRequestType(t *testing.T) {

	testParseRequestType(t, nil, false, requestDirectHTTP)
	testParseRequestType(t, nil, true, requestDirectHTTPS)

	s, _ := superproxy.NewSuperProxy("0.0.0.0", 8080, superproxy.ProxyTypeHTTP, "", "", "")
	testParseRequestType(t, s, false, requestProxyHTTP)

	s, _ = superproxy.NewSuperProxy("0.0.0.0", 8080, superproxy.ProxyTypeHTTPS, "", "", "")
	testParseRequestType(t, s, false, requestProxyHTTP)

	s, _ = superproxy.NewSuperProxy("0.0.0.0", 8080, superproxy.ProxyTypeHTTPS, "", "", "")
	testParseRequestType(t, s, true, requestProxyHTTPS)

	s, _ = superproxy.NewSuperProxy("0.0.0.0", 8080, superproxy.ProxyTypeSOCKS5, "", "", "")
	testParseRequestType(t, s, false, requestProxySOCKS5)
}

func testParseRequestType(t *testing.T, s *superproxy.SuperProxy, isTLS bool, expReqType requestType) {
	vRequest := &VariedRequest{}
	vRequest.SetProxy(s)
	vRequest.SetIsTLS(isTLS)
	reqType := parseRequestType(vRequest.GetProxy(), vRequest.IsTLS())
	if reqType != expReqType {
		t.Fatal("reqType should be requestDirectHTTP")
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
