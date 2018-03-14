package http

import (
	"bufio"
	"bytes"
	"io"
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

func TestHostInfo(t *testing.T) {
	hostInfo := &HostInfo{}
	hostInfo.ParseHostWithPort("127.0.0.1:8080")
	hostInfo.SetIP([]byte("114.114.114.114"))

	if hostInfo.HostWithPort() != "127.0.0.1:8080" {
		t.Fatal("Host with port is wrong")
	}

	if !bytes.Equal(hostInfo.IP(), []byte("114.114.114.114")) {
		t.Fatal("Setting IP is wrong")
	}

	if hostInfo.Port() != "8080" {
		t.Fatal("Parsing port is wrong")
	}

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

type hijacker struct{}

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
