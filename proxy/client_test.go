package proxy

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

func TestParallelWriteHeader(t *testing.T) {
	buffer1 := bytebufferpool.Get()
	defer bytebufferpool.Put(buffer1)

	var additionalDst string
	n, err := parallelWriteHeader(buffer1, func(p []byte) { additionalDst = string(p) }, []byte("Host: www.google.com\r\nUser-Agent: curl/7.54.0\r\n\r\n"))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if n != len(additionalDst) {
		t.Fatalf("parallelWriteHeader function work error: %d != %d", n, len(additionalDst))
	}
	if len(buffer1.B) != len(additionalDst) {
		t.Fatalf("parallelWriteHeader function work error: %d != %d", len(buffer1.B), len(additionalDst))
	}
	if !strings.Contains(string(buffer1.B), additionalDst) {
		t.Fatal("error: additionalDst is not save buffer data")
	}
	buffer1.Reset()

	n, err = parallelWriteHeader(buffer1, func(p []byte) { additionalDst = string(p) }, []byte("Host: www.google.com\r\nUser-Agent: curl/7.54.0\n\n"))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if n != len(additionalDst) {
		t.Fatalf("parallelWriteHeader function work error: %d != %d", n, len(additionalDst))
	}
	if len(buffer1.B) != len(additionalDst) {
		t.Fatalf("parallelWriteHeader function work error: %d != %d", len(buffer1.B), len(additionalDst))
	}
	if !strings.Contains(string(buffer1.B), additionalDst) {
		t.Fatal("error: additionalDst is not save buffer data")
	}
	buffer1.Reset()

	n, err = parallelWriteHeader(buffer1, func(p []byte) { additionalDst = string(p) }, []byte("Host: www.google.com\r\nProxy-Connection: Keep-Alive\r\nUser-Agent: curl/7.54.0\r\n\r\n"))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if n != (len(additionalDst) - len("Proxy-Connection: Keep-Alive\r\n")) {
		t.Fatalf("parallelWriteHeader function work error: %d != %d", n, (len(additionalDst) - len("Proxy-Connection: Keep-Alive\r\n")))
	}
	if len(buffer1.B) != n {
		t.Fatalf("parallelWriteHeader function work error: %d != %d", len(buffer1.B), n)
	}
	if bytes.Contains(buffer1.B, []byte("Proxy-Connection: Keep-Alive\r\n")) {
		t.Fatalf("buffer couldn't has this message: %s", "Proxy-Connection: Keep-Alive\r\n")
	}
	if !strings.Contains(additionalDst, "Proxy-Connection: Keep-Alive\r\n") {
		t.Fatalf("buffer should has this message: %s", "Proxy-Connection: Keep-Alive\r\n")
	}

	fixedsizebytebuffer := bytebufferpool.MakeFixedSizeByteBuffer(5)
	n, err = parallelWriteHeader(fixedsizebytebuffer, func(p []byte) { additionalDst = string(p) }, []byte("Host: www.google.com\r\nProxy-Connection: Keep-Alive\r\nUser-Agent: curl/7.54.0\r\n\r\n"))
	if err == nil {
		t.Fatal("expected error: error short buffer")
	}
	if !strings.Contains(err.Error(), "error short buffer") {
		t.Fatalf("expected error: error short buffer, but error: %s", err)
	}
}

func TestHTTPRequest(t *testing.T) {
	s := "GET / HTTP/1.1\r\n" +
		"Host: localhost:10000\r\n" +
		"\r\n"
	req := &Request{}
	br := bufio.NewReader(strings.NewReader(s))
	lineSize, err := req.parseStartLine(br)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if !bytes.Equal(req.Method(), []byte("GET")) {
		t.Fatalf("Read from bufio reader is error")
	}
	if lineSize != 16 {
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
	_, _, err = req.WriteHeaderTo(bw)
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
	_, err := req.parseStartLine(br)
	if err == nil {
		t.Fatal("expected error: fail to read start line of request")
	}
	if !strings.Contains(err.Error(), "fail to read start line of request") {
		t.Fatalf("unexpected error: %s", err.Error())
	}

	req.Reset()
	nbr := bufio.NewReader(strings.NewReader(rightReq))
	req.parseStartLine(nbr)
	_, err = req.parseStartLine(nbr)
	if err == nil {
		t.Fatal("expected error: request already initialized")
	}
	if !strings.Contains(err.Error(), "request already initialized") {
		t.Fatalf("unexpected error: %s", err.Error())
	}

	req.Reset()
	_, err = req.parseStartLine(nil)
	if err == nil {
		t.Fatal("nil reader provided")
	}
	if !strings.Contains(err.Error(), "nil reader provided") {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	w := bytebufferpool.Get()
	bw := bufio.NewWriter(w)
	_, _, err = req.WriteHeaderTo(bw)
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

	n, err := resp.ReadFrom(false, br)
	if n != 43 {
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

	_, err = resp.ReadFrom(false, br)
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

func TestWithClient(t *testing.T) {
	go func() {
		nethttp.HandleFunc("/client", func(w nethttp.ResponseWriter, r *nethttp.Request) {
			fmt.Fprint(w, "Hello world!")
		})
		log.Fatal(nethttp.ListenAndServe(":10000", nil))
	}()
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &client.Client{
		BufioPool: bPool,
	}
	getReq := "GET /client HTTP/1.1\r\n" +
		"Host: 127.0.0.1:10000\r\n" +
		"\r\n"
	req := &Request{}
	req.Reset()
	br := bufio.NewReader(strings.NewReader(getReq))
	_, err := req.parseStartLine(br)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	req.reqLine.HostInfo().ParseHostWithPort("127.0.0.1:10000", false)
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
	_, _, respSize, err := c.Do(req, resp)
	if err != nil {
		t.Fatalf("unexpected error : %s", err.Error())
	}
	if respSize == 0 {
		t.Fatalf("No response data can get, client do with proxy http request and response error")
	}
	if !bytes.Contains(resp.respLine.GetResponseLine(), []byte("HTTP/1.1 200 OK")) {
		t.Fatalf("No response data can get, client do with proxy http request and response error")
	}
	if !bytes.Contains(bReq.Bytes(), []byte("Host")) {
		t.Fatal("Hijack does not save request data")
	}
	req.Reset()
	resp.Reset()
	headReq := "HEAD /client HTTP/1.1\r\n" +
		"Host: 127.0.0.1:10000\r\n" +
		"\r\n"
	br = bufio.NewReader(strings.NewReader(headReq))
	_, err = req.parseStartLine(br)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	req.reqLine.HostInfo().ParseHostWithPort("127.0.0.1:10000", false)
	req.SetHijacker(sHijack)
	b = bytebufferpool.MakeFixedSizeByteBuffer(100)
	bw = bufio.NewWriter(b)
	resp = &Response{}
	err = resp.WriteTo(bw)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	resp.SetHijacker(sHijack)
	_, _, respSize, err = c.Do(req, resp)
	if err != nil {
		t.Fatalf("unexpected error : %s", err.Error())
	}
	if respSize == 0 {
		t.Fatalf("No response data can get, client do with proxy http request and response error")
	}
	if !bytes.Contains(resp.respLine.GetResponseLine(), []byte("HTTP/1.1 200 OK")) {
		t.Fatalf("No response data can get, client do with proxy http request and response error")
	}

	req.Reset()
	resp.Reset()
	postReq := "POST /client HTTP/1.1\r\n" +
		"Host: 127.0.0.1:10000\r\n" +
		"\r\n"
	br = bufio.NewReader(strings.NewReader(postReq))
	_, err = req.parseStartLine(br)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	req.reqLine.HostInfo().ParseHostWithPort("127.0.0.1:10000", false)
	req.SetHijacker(sHijack)
	b = bytebufferpool.MakeFixedSizeByteBuffer(100)
	bw = bufio.NewWriter(b)
	resp = &Response{}
	err = resp.WriteTo(bw)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	resp.SetHijacker(sHijack)
	_, _, respSize, err = c.Do(req, resp)
	if err != nil {
		t.Fatalf("unexpected error : %s", err.Error())
	}
	if respSize == 0 {
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

var bReq = bytebufferpool.MakeFixedSizeByteBuffer(100)
var bResp = bytebufferpool.MakeFixedSizeByteBuffer(100)

type hijacker struct {
	clientAddr, targetHost string
	method, path           []byte
}

func (s *hijacker) OnRequest(header http.Header, rawHeader []byte) io.Writer {
	bReq.Write(rawHeader)
	return bReq
}

func (s *hijacker) HijackResponse() io.Reader {
	return nil
}

func (s *hijacker) OnResponse(respLine http.ResponseLine,
	header http.Header, rawHeader []byte) io.Writer {
	fmt.Fprintf(bResp, `
			************************
			%s %d %s
			************************
			content length: %d
			content type: %s
			************************
			%s
			************************
			`,

		respLine.GetProtocol(), respLine.GetStatusCode(), respLine.GetStatusMessage(),
		header.ContentLength(), header.ContentType(), rawHeader)
	return bResp
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
	n, _, err := copyHeader(h, br, bw, testF)
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
	n, _, err = copyHeader(h, ebr, bw, testF)
	if err == nil {
		t.Fatalf("unexpected error: fail to parse header")
	}
	if !strings.Contains(err.Error(), "fail to parse http headers") {
		t.Fatalf("unexpected error: %s", err.Error())
	}
}

func TestRequestPool(t *testing.T) {
	for i := 0; i < 10; i++ {
		reqPool := &RequestPool{}
		request := reqPool.Acquire()
		/*if request. != 0 {
			t.Fatal("request pool can't acquire an empty request")
		}
		request.AddWriteSize(10)
		if request.GetWriteSize() != 10 {
			t.Fatal("request pool can't acquire an normal request")
		}*/
		reqPool.Release(request)
	}
}

func TestResponsePool(t *testing.T) {
	//s := "HTTP/1.1 200 ok\r\n\r\n"
	for i := 0; i < 10; i++ {
		respPool := &ResponsePool{}
		resp := respPool.Acquire()
		/*if resp.GetSize() != 0 {
			t.Fatal("request pool can't acquire an empty response")
		}
		br := bufio.NewReader(strings.NewReader(s))
		byteBuffer := bytebufferpool.MakeFixedSizeByteBuffer(100)
		bw := bufio.NewWriter(byteBuffer)
		sHijacker := &simpleHijacker{}
		resp.SetHijacker(sHijacker)
		err := resp.WriteTo(bw)
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		err = resp.ReadFrom(false, br)
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		if resp.GetSize() != 19 {
			t.Fatal("request pool can't acquire an normal response")
		}*/
		respPool.Release(resp)
	}
}

type simpleHijacker struct{}

func (s *simpleHijacker) OnRequest(header http.Header, rawHeader []byte) io.Writer {
	return nil
}

func (s *simpleHijacker) HijackResponse() io.Reader {
	return nil
}

func (s *simpleHijacker) OnResponse(respLine http.ResponseLine,
	header http.Header, rawHeader []byte) io.Writer {
	return nil
}
