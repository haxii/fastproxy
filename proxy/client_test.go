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
	fixedsizebytebuffer := bytebufferpool.MakeFixedSizeByteBuffer(5)
	testParallelWriteHeader(t, buffer1, nil, []byte("Host: www.google.com\r\nUser-Agent: curl/7.54.0\r\n\r\n"), "", "")
	buffer1.Reset()
	testParallelWriteHeader(t, buffer1, nil, []byte("Host: www.google.com\r\nUser-Agent: curl/7.54.0\n\n"), "", "")
	buffer1.Reset()
	testParallelWriteHeader(t, buffer1, nil, []byte("Host: www.google.com\r\nProxy-Connection: Keep-Alive\r\nUser-Agent: curl/7.54.0\r\n\r\n"), "", "Proxy-Connection: Keep-Alive\r\n")
	testParallelWriteHeader(t, nil, fixedsizebytebuffer, []byte("Host: www.google.com\r\nProxy-Connection: Keep-Alive\r\nUser-Agent: curl/7.54.0\r\n\r\n"), "error short buffer", "")
}

func testParallelWriteHeader(t *testing.T, buffer *bytebufferpool.ByteBuffer, fixedsizeB *bytebufferpool.FixedSizeByteBuffer, header []byte, expErr, expResult string) {
	var additionalDst string
	if buffer != nil {
		n, err := parallelWriteHeader(buffer, func(p []byte) { additionalDst = string(p) }, header)
		if err != nil {
			if !strings.Contains(err.Error(), expErr) {
				t.Fatalf("expected error: error short buffer, but error: %s", err)
			}
		}
		if len(expResult) > 0 {
			if bytes.Contains(buffer.B, []byte(expResult)) {
				t.Fatalf("buffer couldn't has this message: %s", expResult)
			}
			if !strings.Contains(additionalDst, expResult) {
				t.Fatalf("buffer should has this message: %s", expResult)
			}

			if n != (len(additionalDst) - len(expResult)) {
				t.Fatalf("parallelWriteHeader function work error: %d != %d", n, (len(additionalDst) - len(expResult)))
			}
			if len(buffer.B) != n {
				t.Fatalf("parallelWriteHeader function work error: %d != %d", len(buffer.B), n)
			}
		}
	} else {
		_, err := parallelWriteHeader(fixedsizeB, func(p []byte) { additionalDst = string(p) }, header)
		if err != nil {
			if !strings.Contains(err.Error(), expErr) {
				t.Fatalf("expected error: error short buffer, but error: %s", err)
			}
		}
	}
}

func TestHTTPRequest(t *testing.T) {
	testRequest(t, "GET / HTTP/1.1\r\n\r\n", "GET", "HTTP/1.1", 16, "", 0)
	testRequest(t, "GET / HTTP/1.1\n\n", "GET", "HTTP/1.1", 15, "", 0)
	testRequest(t, "GET / HTTP/1.0\r\n\r\n", "GET", "HTTP/1.0", 16, "", 0)
	testRequest(t, "GET / HTTP/1.1\r\nHost: localhost:10000\r\n\r\n", "GET", "HTTP/1.1", 16, "", 22)

	testRequest(t, "/ HTTP/1.1\r\n\r\n", "", "", 0, "fail to read start line of request", 0)
	testRequest(t, "GET HTTP/1.1\r\n\r\n", "", "", 0, "fail to read start line of request", 0)
	testRequest(t, "GET / \r\n\r\n", "GET", "", 8, "fail to read start line of request", 0)
	testRequest(t, "GET / HTTP/1.1", "", "", 0, io.EOF.Error(), 0)
}

func testRequest(t *testing.T, reqString string, expMethod string, expProtocol string, expSize int, expErr string, expHeaderSize int) {
	req := &Request{}
	br := bufio.NewReader(strings.NewReader(reqString))
	lineSize, err := req.parseStartLine(br)
	if err != nil {
		if !strings.Contains(err.Error(), expErr) {
			t.Fatalf("unexpected error: %s", err)
		}
	} else {
		if !bytes.Equal(req.Method(), []byte(expMethod)) {
			t.Fatalf("Read from bufio reader is error")
		}
		if lineSize != expSize {
			t.Fatalf("Read from bufio reader size is error")
		}
		if !bytes.Equal(req.Protocol(), []byte(expProtocol)) {
			t.Fatalf("Protocol parse error")
		}
		w := bytebufferpool.Get()
		bw := bufio.NewWriter(w)
		sHijacker := &hijacker{}
		req.SetHijacker(sHijacker)
		_, _, err = req.WriteHeaderTo(bw)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if bw.Buffered() == expHeaderSize {
			fmt.Println(bw.Buffered())
			t.Fatalf("Cant't write header to bufio writer")
		}
	}
}

func testResponse(t *testing.T, respString string, expErr string, expSize int) {
	resp := &Response{}
	bPool := bufiopool.New(1, 1)
	br := bPool.AcquireReader(strings.NewReader(respString))
	byteBuffer := bytebufferpool.MakeFixedSizeByteBuffer(100)
	bw := bufio.NewWriter(byteBuffer)
	err := resp.WriteTo(bw)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	sHijacker := &hijacker{}
	resp.SetHijacker(sHijacker)

	n, err := resp.ReadFrom(false, br)
	if err != nil {
		if !strings.Contains(err.Error(), expErr) {
			t.Fatalf("unexpected error: %s", err)
		}
	} else {
		if n != expSize {
			t.Fatal("Response read from reader failed")
		}
	}
	defer bw.Flush()
}

func TestHTTPResponse(t *testing.T) {
	s := "HTTP/1.1 200 ok\r\n" +
		"Cache-Control:no-cache\r\n" +
		"\r\n"
	testResponse(t, s, "", len(s))
	s = "HTTP/1.1 200 ok\n"
	testResponse(t, s, "", len(s))
	s = "HTTP/1.1 ok\r\nConnection:close\r\n\r\n"
	testResponse(t, s, "fail to read start line of response", 0)
	s = "HTTP/1.1 200\r\nConnection:close\r\n\r\n"
	testResponse(t, s, "fail to read start line of response", 0)
	s = "200 ok\r\nConnection:close\r\n\r\n"
	testResponse(t, s, "fail to read start line of response", 0)
	s = "HTTP/1.1 200 ok"
	testResponse(t, s, io.EOF.Error(), 0)
}

func testWithClient(t *testing.T, reqString string) {
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &client.Client{
		BufioPool: bPool,
	}
	req := &Request{}
	req.Reset()
	br := bufio.NewReader(strings.NewReader(reqString))
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
}

func TestWithClient(t *testing.T) {
	go func() {
		nethttp.HandleFunc("/client", func(w nethttp.ResponseWriter, r *nethttp.Request) {
			fmt.Fprint(w, "Hello world!")
		})
		log.Fatal(nethttp.ListenAndServe(":10000", nil))
	}()
	getReq := "GET /client HTTP/1.1\r\n" +
		"Host: 127.0.0.1:10000\r\n" +
		"\r\n"
	headReq := "HEAD /client HTTP/1.1\r\n" +
		"Host: 127.0.0.1:10000\r\n" +
		"\r\n"
	postReq := "POST /client HTTP/1.1\r\n" +
		"Host: 127.0.0.1:10000\r\n" +
		"\r\n"

	testWithClient(t, getReq)
	testWithClient(t, headReq)
	testWithClient(t, postReq)
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
