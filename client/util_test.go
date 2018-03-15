package client

import (
	"bufio"
	"io"
	"testing"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/bytebufferpool"
	"github.com/haxii/fastproxy/superproxy"
)

func TestWriteRequestLine(t *testing.T) {
	var err error
	w := bytebufferpool.MakeFixedSizeByteBuffer(100)
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	bw := bPool.AcquireWriter(w)
	n, err := writeRequestLine(bw, false, []byte("GET"), "127.0.0.1:8080", []byte("/"), []byte("HTTP/1.1"))
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}

	if bw.Buffered() != n {
		t.Fatal("Write data error")
	}
	bw.Reset(w)

	n, err = writeRequestLine(bw, true, []byte("GET"), "127.0.0.1:8080", []byte("/"), []byte("HTTP/1.1"))
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}

	if bw.Buffered() != n {
		t.Fatal("Write data error")
	}
	bw.Reset(w)

	n, err = writeRequestLine(bw, true, []byte("GET"), "127.0.0.1:8080", []byte("/"), []byte("HTTP/1.1"))
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if bw.Buffered() != n {
		t.Fatal("Write data error")
	}
	bw.Reset(w)

	_, err = writeRequestLine(nil, false, []byte("GET"), "127.0.0.1:8080", []byte("/"), []byte("HTTP/1.1"))
	if err != errNilBufiopool {
		t.Fatalf("Expected error is nil pool, but get unexpected errror: %s", err.Error())
	}
	bw.Reset(w)

	method := ""
	for i := 0; i < 10000; i++ {
		method += "G"
	}
	n, err = writeRequestLine(bw, false, []byte(method), "", nil, nil)
	if err != io.ErrShortBuffer {
		t.Fatalf("Expected error is nil pool, but get unexpected error: %s", err.Error())
	}
	if n > 4096 {
		t.Fatal("Should not write all data in bufio writer")
	}
	bw.Reset(w)

	hostwithport := ""
	for i := 0; i < 10000; i++ {
		hostwithport += "G"
	}
	hostwithport += ".0.0.0:8080"
	n, err = writeRequestLine(bw, false, []byte("GET"), hostwithport, []byte("/"), []byte("HTTP/1.1"))
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if n > 4096 {
		t.Fatal("Should not write all data in bufio writer")
	}
	bw.Reset(w)

	path := ""
	for i := 0; i < 10000; i++ {
		path += "/"
	}
	n, err = writeRequestLine(bw, false, []byte("GET"), "127.0.0.1:8080", []byte(path), []byte("HTTP/1.1"))
	if err != io.ErrShortBuffer {
		t.Fatalf("Expected error is nil pool, but get unexpected error: %s", err.Error())
	}
	if n > 4096 {
		t.Fatal("Should not write all data in bufio writer")
	}
	bw.Reset(w)

	protocol := ""
	for i := 0; i < 10000; i++ {
		protocol += "HTTP/1.1"
	}
	n, err = writeRequestLine(bw, false, []byte("GET"), "127.0.0.1:8080", []byte("/"), []byte(protocol))
	if err != io.ErrShortBuffer {
		t.Fatalf("Expected error is nil pool, but get unexpected error: %s", err.Error())
	}
	if n > 4096 {
		t.Fatal("Should not write all data in bufio writer")
	}

	defer bPool.ReleaseWriter(bw)
}

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
