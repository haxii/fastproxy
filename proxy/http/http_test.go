package http

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	nethttp "net/http"
	"strings"
	"testing"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/bytebufferpool"
	"github.com/haxii/fastproxy/client"
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
	w := bytebufferpool.Get()
	bw := bufio.NewWriter(w)
	sHijacker := &hijacker{}
	req.SetHijacker(sHijacker)
	err = req.WriteHeaderTo(bw)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if bw.Buffered() == 0 {
		t.Fatalf("Cant't write header to bufio writer")
	}
}

func TestHTTPRequestError(t *testing.T) {
	errorReq := "/ HTTP/1.1\r\n" +
		"Host: localhost:10000\r\n" +
		"\r\n"
	rightReq := "GET / HTTP/1.1\r\n" +
		"Host: localhost:10000\r\n" +
		"\r\n"
	req := &Request{}
	br := bufio.NewReader(strings.NewReader(errorReq))
	err := req.ReadFrom(br)
	if err == nil {
		t.Fatal("expected error: fail to read start line of request")
	}
	if !strings.Contains(err.Error(), "fail to read start line of request") {
		t.Fatalf("unexpected error: %s", err.Error())
	}

	req.Reset()
	nbr := bufio.NewReader(strings.NewReader(rightReq))
	req.ReadFrom(nbr)
	err = req.ReadFrom(nbr)
	if err == nil {
		t.Fatal("expected error: request already initialized")
	}
	if !strings.Contains(err.Error(), "request already initialized") {
		t.Fatalf("unexpected error: %s", err.Error())
	}

	req.Reset()
	err = req.ReadFrom(nil)
	if err == nil {
		t.Fatal("nil reader provided")
	}
	if !strings.Contains(err.Error(), "nil reader provided") {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	w := bytebufferpool.Get()
	bw := bufio.NewWriter(w)
	err = req.WriteHeaderTo(bw)
	if err == nil {
		t.Fatal("expected error:Empty request, nothing to write")
	}
	if !strings.Contains(err.Error(), "Empty request, nothing to write") {
		t.Fatalf("unexpected error: %s", err)
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

func TestHTTPResponseError(t *testing.T) {
	errS := "HTTP/1.1 ok\r\n" +
		"Cache-Control:no-cache\r\n" +
		"\r\n"
	resp := &Response{}
	bPool := bufiopool.New(1, 1)
	br := bPool.AcquireReader(strings.NewReader(errS))
	byteBuffer := bytebufferpool.MakeFixedSizeByteBuffer(100)
	bw := bufio.NewWriter(byteBuffer)
	err := resp.WriteTo(bw)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	sHijacker := &hijacker{}
	resp.SetHijacker(sHijacker)

	err = resp.ReadFrom(false, br)
	if !strings.Contains(err.Error(), "fail to read start line of response") {
		t.Fatalf("unexpected error: %s", err)
	}
	err = resp.WriteTo(bw)
	if err == nil {
		t.Fatalf("expected error: %s", err)
	}
	if !strings.Contains(err.Error(), "response already initialized") {
		t.Fatalf("unexpected error: %s", err)
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

func TestWithClient(t *testing.T) {
	go func() {
		nethttp.HandleFunc("/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
			fmt.Fprint(w, "Hello world!")
		})
		log.Fatal(nethttp.ListenAndServe(":10000", nil))
	}()
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &client.Client{
		BufioPool: bPool,
	}
	getReq := "GET / HTTP/1.1\r\n" +
		"Host: localhost:10000\r\n" +
		"\r\n"
	req := &Request{}
	br := bufio.NewReader(strings.NewReader(getReq))
	err := req.ReadFrom(br)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	req.SetHostWithPort("127.0.0.1:10000")
	sHijack := &simpleHijacker{}
	req.SetHijacker(sHijack)
	b := bytebufferpool.MakeFixedSizeByteBuffer(100)
	bw := bufio.NewWriter(b)
	resp := &Response{}
	err = resp.WriteTo(bw)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	resp.SetHijacker(sHijack)
	err = c.Do(req, resp)
	if err != nil {
		t.Fatalf("unexpected error : %s", err.Error())
	}
	if resp.GetSize() == 0 {
		t.Fatalf("No response data can get, client do with proxy http request and response error")
	}
	if !bytes.Contains(resp.respLine.GetResponseLine(), []byte("HTTP/1.1 200 OK")) {
		t.Fatalf("No response data can get, client do with proxy http request and response error")
	}

	req.Reset()
	resp.Reset()
	headReq := "HEAD / HTTP/1.1\r\n" +
		"Host: localhost:10000\r\n" +
		"\r\n"
	br = bufio.NewReader(strings.NewReader(headReq))
	err = req.ReadFrom(br)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	req.SetHostWithPort("127.0.0.1:10000")
	req.SetHijacker(sHijack)
	b = bytebufferpool.MakeFixedSizeByteBuffer(100)
	bw = bufio.NewWriter(b)
	resp = &Response{}
	err = resp.WriteTo(bw)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	resp.SetHijacker(sHijack)
	err = c.Do(req, resp)
	if err != nil {
		t.Fatalf("unexpected error : %s", err.Error())
	}
	if resp.GetSize() == 0 {
		t.Fatalf("No response data can get, client do with proxy http request and response error")
	}
	if !bytes.Contains(resp.respLine.GetResponseLine(), []byte("HTTP/1.1 200 OK")) {
		t.Fatalf("No response data can get, client do with proxy http request and response error")
	}

	req.Reset()
	resp.Reset()
	postReq := "POST / HTTP/1.1\r\n" +
		"Host: localhost:10000\r\n" +
		"\r\n"
	br = bufio.NewReader(strings.NewReader(postReq))
	err = req.ReadFrom(br)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	req.SetHostWithPort("127.0.0.1:10000")
	req.SetHijacker(sHijack)
	b = bytebufferpool.MakeFixedSizeByteBuffer(100)
	bw = bufio.NewWriter(b)
	resp = &Response{}
	err = resp.WriteTo(bw)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	resp.SetHijacker(sHijack)
	err = c.Do(req, resp)
	if err != nil {
		t.Fatalf("unexpected error : %s", err.Error())
	}
	if resp.GetSize() == 0 {
		t.Fatalf("No response data can get, client do with proxy http request and response error")
	}
	if !bytes.Contains(resp.respLine.GetResponseLine(), []byte("HTTP/1.1 200 OK")) {
		t.Fatalf("No response data can get, client do with proxy http request and response error")
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

func TestCopyHeader(t *testing.T) {
	h := &http.Header{}
	rightReq := "GET / HTTP/1.1\r\n" +
		"Host: localhost:10000\r\n" +
		"\r\n"
	br := bufio.NewReader(strings.NewReader(rightReq))
	byteBuffer := bytebufferpool.MakeFixedSizeByteBuffer(100)
	bw := bufio.NewWriter(byteBuffer)
	testF := func(b []byte) {
		return
	}
	n, err := copyHeader(h, br, bw, testF)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if n != bw.Buffered() {
		t.Fatalf("Copy header is error")
	}

	h.Reset()
	errReq := ""
	ebr := bufio.NewReader(strings.NewReader(errReq))
	byteBuffer = bytebufferpool.MakeFixedSizeByteBuffer(100)
	bw = bufio.NewWriter(byteBuffer)
	testF = func(b []byte) {
		return
	}
	n, err = copyHeader(h, ebr, bw, testF)
	if err == nil {
		t.Fatalf("unexpected error: fail to parse header")
	}
	if !strings.Contains(err.Error(), "fail to parse http headers") {
		t.Fatalf("unexpected error: %s", err.Error())
	}

}
