package client

import (
	"bufio"
	"fmt"
	"io"
	"log"
	nethttp "net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/bytebufferpool"
	"github.com/haxii/fastproxy/http"
	proxyhttp "github.com/haxii/fastproxy/proxy/http"
)

func TestClientDo(t *testing.T) {
	go func() {
		nethttp.HandleFunc("/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
			fmt.Fprintf(w, "Hello world,tteterete%s!\r\n", r.URL.Path[1:])
		})
		log.Fatal(nethttp.ListenAndServe(":10000", nil))
	}()
	testClientDoByDefaultParamters(t)

	testClientDoWithErrorParamters(t)

	testClientDoWithEmptyRequestAndResponse(t)

	testClientDoTimeoutSuccess(t, nil, 10)
	testClientDoConcurrent(t)

	testClientDoTimeoutError(t, nil, 10)
	testClientDoReadTimeoutErrorConcurrent(t)

	testClientDoIsIdempotent(t)

	testHostClientPendingRequests(t)
}

func testClientDoByDefaultParamters(t *testing.T) {
	var err error
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &Client{
		BufioPool: bPool,
	}
	s := "GET / HTTP/1.1\r\n" +
		"Host: localhost:10000\r\n" +
		"\r\n"
	req := &proxyhttp.Request{}
	sHijacker := &hijacker{}
	req.SetHijacker(sHijacker)
	br := bufio.NewReader(strings.NewReader(s))
	err = req.ReadFrom(br)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	req.SetHostWithPort("localhost:10000")
	resp := &proxyhttp.Response{}
	byteBuffer := bytebufferpool.MakeFixedSizeByteBuffer(100)
	bw := bufio.NewWriter(byteBuffer)
	err = resp.WriteTo(bw)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	resp.SetHijacker(sHijacker)
	err = c.Do(req, resp)
	if err != nil {
		t.Fatalf("unexpected error : %s", err.Error())
	}
	if resp.GetSize() == 0 {
		t.Fatal("Response can't be empty")
	}
	if bw.Buffered() == 0 {
		t.Fatal("Response don't write to bufio writer")
	}
	defer bw.Flush()
}

func testClientDoConcurrent(t *testing.T) {
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &Client{
		BufioPool:       bPool,
		MaxConnsPerHost: 50,
		ReadTimeout:     time.Second,
	}
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			testClientDoTimeoutSuccess(t, c, 10)
		}()
	}
	wg.Wait()
}
func testClientDoTimeoutSuccess(t *testing.T, c *Client, n int) {
	var err error
	s := "GET / HTTP/1.1\r\n" +
		"Host: localhost:10000\r\n" +
		"\r\n"
	if c == nil {
		bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
		c = &Client{
			BufioPool:   bPool,
			ReadTimeout: time.Second,
		}
	}
	for i := 0; i < n; i++ {
		req := &proxyhttp.Request{}
		sHijacker := &hijacker{}
		req.SetHijacker(sHijacker)
		br := bufio.NewReader(strings.NewReader(s))
		err = req.ReadFrom(br)
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		req.SetHostWithPort("localhost:10000")
		resp := &proxyhttp.Response{}
		byteBuffer := bytebufferpool.MakeFixedSizeByteBuffer(100)
		bw := bufio.NewWriter(byteBuffer)
		err = resp.WriteTo(bw)
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		resp.SetHijacker(sHijacker)

		err = c.Do(req, resp)
		if err != nil {
			t.Fatalf("unexpecting error: %s", err.Error())
		}
		defer bw.Flush()
	}
}
func testClientDoReadTimeoutErrorConcurrent(t *testing.T) {
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &Client{
		BufioPool:       bPool,
		MaxConnsPerHost: 1000,
		ReadTimeout:     time.Millisecond,
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			testClientDoTimeoutError(t, c, 100)
		}()
	}
	wg.Wait()
}

func testClientDoWithErrorParamters(t *testing.T) {
	s := "GET / HTTP/1.1\r\n" +
		"Host: localhost:10000\r\n" +
		"\r\n"
	errS := "GET / HTTP/1.1\r\n" +
		"\r\n"
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)

	req := &proxyhttp.Request{}
	sHijacker := &hijacker{}
	req.SetHijacker(sHijacker)
	br := bufio.NewReader(strings.NewReader(s))
	err := req.ReadFrom(br)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	resp := &proxyhttp.Response{}
	byteBuffer := bytebufferpool.MakeFixedSizeByteBuffer(100)
	bw := bufio.NewWriter(byteBuffer)
	err = resp.WriteTo(bw)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	resp.SetHijacker(sHijacker)

	testClientDoWithErrorParamter(t, nil, req, resp, s, errNilBufiopool)
	testClientDoWithErrorParamter(t, bPool, req, resp, errS, errNilTargetHost)

}

func testClientDoWithErrorParamter(t *testing.T, bPool *bufiopool.Pool, req *proxyhttp.Request, resp *proxyhttp.Response, s string, expErr error) {
	c := &Client{
		BufioPool: bPool,
	}
	err := c.Do(req, resp)
	if err == nil {
		t.Fatal("expecting error")
	}
	if err != expErr {
		t.Fatalf("unexpected error: %s", err.Error())
	}

}

func testClientDoWithEmptyRequestAndResponse(t *testing.T) {
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)

	req := &proxyhttp.Request{}
	resp := &proxyhttp.Response{}
	c := &Client{
		BufioPool: bPool,
	}
	err := c.Do(nil, resp)
	if err == nil {
		t.Fatal("expecting error")
	}
	if err != errNilReq {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	err = c.Do(req, nil)
	if err == nil {
		t.Fatal("expecting error")
	}
	if err != errNilResp {
		t.Fatalf("unexpected error: %s", err.Error())
	}
}

func testClientDoTimeoutError(t *testing.T, c *Client, n int) {
	var err error
	s := "GET / HTTP/1.1\r\n" +
		"Host: localhost:10000\r\n" +
		"\r\n"
	if c == nil {
		bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
		c = &Client{
			BufioPool:   bPool,
			ReadTimeout: time.Millisecond,
		}
	}
	for i := 0; i < n; i++ {
		req := &proxyhttp.Request{}
		sHijacker := &hijacker{}
		req.SetHijacker(sHijacker)
		br := bufio.NewReader(strings.NewReader(s))
		err = req.ReadFrom(br)
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		req.SetHostWithPort("localhost:10000")
		resp := &proxyhttp.Response{}
		byteBuffer := bytebufferpool.MakeFixedSizeByteBuffer(100)
		bw := bufio.NewWriter(byteBuffer)
		err = resp.WriteTo(bw)
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		resp.SetHijacker(sHijacker)

		err = c.Do(req, resp)
		if err == nil {
			t.Fatal("expecting error")
		}
		if !strings.Contains(err.Error(), "timeout") {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		defer bw.Flush()
	}
}

func testClientDoIsIdempotent(t *testing.T) {
	s := "GET / HTTP/1.1\r\n" +
		"Host: localhost:10000\r\n" +
		"\r\n"
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &Client{
		BufioPool: bPool,
	}
	req := &proxyhttp.Request{}
	sHijacker := &hijacker{}
	req.SetHijacker(sHijacker)
	br := bufio.NewReader(strings.NewReader(s))
	err := req.ReadFrom(br)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	req.SetHostWithPort("localhost:10000")
	resp := &proxyhttp.Response{}
	byteBuffer := bytebufferpool.MakeFixedSizeByteBuffer(100)
	bw := bufio.NewWriter(byteBuffer)
	err = resp.WriteTo(bw)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	resp.SetHijacker(sHijacker)
	err = c.Do(req, resp)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if resp.GetSize() == 0 {
		t.Fatal("Response can't be empty")
	}
	resultSize := resp.GetSize()
	for i := 0; i < 10; i++ {
		req.Reset()
		resp.Reset()

		req.SetHijacker(sHijacker)
		br := bufio.NewReader(strings.NewReader(s))
		err := req.ReadFrom(br)
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		req.SetHostWithPort("localhost:10000")

		err = resp.WriteTo(bw)
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		resp.SetHijacker(sHijacker)
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}

		err = c.Do(req, resp)
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		if resp.GetSize() == 0 {
			t.Fatal("Response can't be empty")
		}
		if resp.GetSize() != resultSize {
			t.Fatalf("Corrent response is not equal with previous response")
		}
	}
	defer bw.Flush()
}

func testHostClientPendingRequests(t *testing.T) {
	concurrency := 10
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &HostClient{
		BufioPool: bPool,
	}
	pendingRequests := c.PendingRequests()
	if pendingRequests != 0 {
		t.Fatalf("non-zero pendingRequests: %d", pendingRequests)
	}
	s := "GET / HTTP/1.1\r\n" +
		"Host: localhost:10000\r\n" +
		"\r\n"

	for i := 0; i < concurrency; i++ {
		req := &proxyhttp.Request{}
		sHijacker := &hijacker{}
		req.SetHijacker(sHijacker)
		br := bufio.NewReader(strings.NewReader(s))
		err := req.ReadFrom(br)
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		req.SetHostWithPort("localhost:10000")
		resp := &proxyhttp.Response{}
		byteBuffer := bytebufferpool.MakeFixedSizeByteBuffer(100)
		bw := bufio.NewWriter(byteBuffer)
		err = resp.WriteTo(bw)
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		resp.SetHijacker(sHijacker)

		if err := c.Do(req, resp); err != nil {
			t.Fatal(err.Error())
			return
		}

		if resp.GetSize() == 0 {
			t.Fatal("Response can't be empty")
			return
		}
	}

	pendingRequests = c.PendingRequests()
	if pendingRequests != 0 {
		t.Fatalf("non-zero pendingRequests: %d", pendingRequests)
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
