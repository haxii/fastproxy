package http

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/fastfork/fastproxy/bufiopool"
	"github.com/fastfork/fastproxy/bytebufferpool"
	"github.com/haxii/fastproxy/http"
)

func TestHTTPRequest(t *testing.T) {
	s := "GET / HTTP/1.1\r\n" +
		"Host: localhost:10000\r\n" +
		"\r\n"
	req := &Request{}
	br := bufio.NewReader(strings.NewReader(s))
	err := req.ReadFrom(br)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if !bytes.Equal(req.Method(), []byte("GET")) {
		t.Fatalf("Read from bufio reader is error")
	}
	if req.GetReqLineSize() != 16 {
		t.Fatalf("Read from bufio reader size is error")
	}
	if !bytes.Equal(req.Protocol(), []byte("HTTP/1.1")) {
		t.Fatalf("Protocol parse error")
	}
	if req.ConnectionClose() {
		t.Fatal("Response connection close is wrong")
	}
	if req.IsTLS() {
		t.Fatal("This is not TLS")
	}
	req.Reset()
	if bytes.Equal(req.Method(), []byte("GET")) {
		t.Fatalf("Reset error")
	}

}

func TestHTTPResponse(t *testing.T) {
	s := "HTTP/1.1 200 ok\r\n" +
		"Cache-Control:no-cache\r\n" +
		"\r\n"
	resp := &Response{}
	bPool := bufiopool.New(1, 1)
	br := bPool.AcquireReader(strings.NewReader(s))
	byteBuffer := bytebufferpool.MakeFixedSizeByteBuffer(100)
	bw := bufio.NewWriter(byteBuffer)
	err := resp.WriteTo(bw)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	sHijacker := &hijacker{}
	addr := testAddr{netWork: "tcp", clientAddr: "127.0.0.1:10000"}
	var clientAddr net.Addr = &addr
	sHijacker.Set(clientAddr, "localhost", []byte("GET"), []byte("/"))

	resp.SetHijacker(sHijacker)

	err = resp.ReadFrom(false, br)
	if resp.GetSize() != 43 {
		t.Fatal("Response read from reader failed")
	}
	if resp.ConnectionClose() {
		t.Fatal("Response connection close is wrong")
	}
	defer bw.Flush()
}

type testAddr struct {
	clientAddr string
	netWork    string
}

func (a *testAddr) String() string {
	return a.clientAddr
}

func (a *testAddr) Network() string {
	return a.netWork
}

type hijacker struct {
	clientAddr, targetHost string
	method, path           []byte
}

func (s *hijacker) Set(clientAddr net.Addr,
	host string, method, path []byte) {
	s.clientAddr = clientAddr.String()
	s.targetHost = host
	s.method = method
	s.path = path
}

func (s *hijacker) OnRequest(header http.Header, rawHeader []byte) io.Writer {
	return nil
}

func (s *hijacker) HijackResponse() io.Reader {
	return nil
}

func (s *hijacker) OnResponse(respLine http.ResponseLine,
	header http.Header, rawHeader []byte) io.Writer {
	return nil
}
