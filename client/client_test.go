package client

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log"
	nethttp "net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/superproxy"
)

func TestClientDo(t *testing.T) {
	go func() {
		nethttp.HandleFunc("/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
			fmt.Fprint(w, "Hello world!")
		})
		log.Fatal(nethttp.ListenAndServe(":10000", nil))
	}()
	time.Sleep(time.Second)
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
	req := &SimpleRequest{}
	req.SetTargetWithPort("0.0.0.0:10000")
	resp := &SimpleResponse{}
	err = c.Do(req, resp)
	if err != nil {
		t.Fatalf("unexpected error : %s", err.Error())
	}
	if !bytes.Contains(resp.GetBody(), []byte("Hello world!")) {
		t.Fatal("Response body is wrong")
	}
}

func testClientDoConcurrentWithLargeNumber(t *testing.T) {
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &Client{
		BufioPool:       bPool,
		MaxConnsPerHost: 50,
	}
	var wg sync.WaitGroup
	for i := 0; i < 51; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			testClientDoTimeoutFailure(t, c, 1000)
		}()
	}
	wg.Wait()
}

func testClientDoTimeoutFailure(t *testing.T, c *Client, n int) {
	var err error
	if c == nil {
		bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
		c = &Client{
			BufioPool:   bPool,
			ReadTimeout: time.Second,
		}
	}
	for i := 0; i < n; i++ {
		req := &SimpleRequest{}
		req.SetTargetWithPort("127.0.0.1:10000")
		resp := &SimpleResponse{}
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}

		err = c.Do(req, resp)
		if err != nil {
			t.Fatalf("unexpecting error: %s", err.Error())
		}
		if !bytes.Contains(resp.GetBody(), []byte("Hello world!")) {
			t.Fatal("Response body is wrong")
		}
	}
}

func testClientDoConcurrent(t *testing.T) {
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &Client{
		BufioPool:       bPool,
		MaxConnsPerHost: 50,
		ReadTimeout:     time.Second,
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			testClientDoTimeoutSuccess(t, c, 1)
		}()
	}
	wg.Wait()
}
func testClientDoTimeoutSuccess(t *testing.T, c *Client, n int) {
	var err error
	if c == nil {
		bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
		c = &Client{
			BufioPool:   bPool,
			ReadTimeout: time.Second,
		}
	}
	for i := 0; i < n; i++ {
		req := &SimpleRequest{}
		req.SetTargetWithPort("127.0.0.1:10000")
		resp := &SimpleResponse{}
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}

		err = c.Do(req, resp)
		if err != nil {
			t.Fatalf("unexpecting error: %s", err.Error())
		}
		if !bytes.Contains(resp.GetBody(), []byte("Hello world!")) {
			t.Fatal("Response body is wrong")
		}
	}
}

func testClientDoReadTimeoutErrorConcurrent(t *testing.T) {
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &Client{
		BufioPool:       bPool,
		MaxConnsPerHost: 1000,
		ReadTimeout:     10 * time.Millisecond,
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
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)

	req := &SimpleRequest{}
	resp := &SimpleResponse{}

	testClientDoWithErrorParamter(t, nil, req, resp, errNilBufiopool)
	testClientDoWithErrorParamter(t, bPool, req, resp, errNilTargetHost)

}

func testClientDoWithErrorParamter(t *testing.T, bPool *bufiopool.Pool, req *SimpleRequest, resp *SimpleResponse, expErr error) {
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

	req := &SimpleRequest{}
	resp := &SimpleResponse{}
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
	if c == nil {
		bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
		c = &Client{
			BufioPool:   bPool,
			ReadTimeout: 10 * time.Millisecond,
		}
	}
	for i := 0; i < n; i++ {
		req := &SimpleRequest{}
		req.SetTargetWithPort("127.0.0.1:10000")
		resp := &SimpleResponse{}

		err = c.Do(req, resp)
		if !strings.Contains(err.Error(), "timeout") {
			t.Fatalf("unexpected error: %s", err.Error())
		}
	}
}

func testClientDoIsIdempotent(t *testing.T) {
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &Client{
		BufioPool: bPool,
	}
	req := &SimpleRequest{}

	req.SetTargetWithPort("127.0.0.1:10000")
	resp := &SimpleResponse{}
	err := c.Do(req, resp)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if resp.GetSize() == 0 {
		t.Fatal("Response can't be empty")
	}
	resultSize := resp.GetSize()
	for i := 0; i < 10; i++ {
		req := &SimpleRequest{}
		req.SetTargetWithPort("127.0.0.1:10000")
		resp := &SimpleResponse{}
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
		if !bytes.Contains(resp.GetBody(), []byte("Hello world!")) {
			t.Fatal("Response body is wrong")
		}
	}
}

func testHostClientPendingRequests(t *testing.T) {
	concurrency := 5
	doneCh := make(chan struct{})
	readyCh := make(chan struct{}, concurrency)
	go func() {
		nethttp.HandleFunc("/hello", func(w nethttp.ResponseWriter, r *nethttp.Request) {
			readyCh <- struct{}{}
			<-doneCh
			//fmt.Fprintf(w, "Hello world,tteterete%s!\r\n", r.URL.Path[1:])
		})
		log.Fatal(nethttp.ListenAndServe(":9999", nil))
	}()

	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &HostClient{
		BufioPool:   bPool,
		ReadTimeout: time.Second,
	}
	pendingRequests := c.PendingRequests()
	if pendingRequests != 0 {
		t.Fatalf("non-zero pendingRequests: %d", pendingRequests)
	}
	resultCh := make(chan error, concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			req := &SimpleRequest{}
			req.SetTargetWithPort("127.0.0.1:9999")
			resp := &SimpleResponse{}
			if err := c.Do(req, resp); err != nil {
				resultCh <- fmt.Errorf("unexpected error: %s", err)
				return
			}

			if resp.GetSize() == 0 {
				resultCh <- fmt.Errorf("Response can't be empty")
				return
			}
			if bytes.Equal(resp.GetBody(), []byte("Hello world!")) {
				resultCh <- fmt.Errorf("Response body is wrong")
				return
			}
			resultCh <- nil
		}()
	}
	for i := 0; i < concurrency; i++ {
		select {
		case <-readyCh:
		case <-time.After(time.Second):
			break
		}
	}

	pendingRequests = c.PendingRequests()
	if pendingRequests != 0 {
		t.Fatalf("non-zero pendingRequests: %d", pendingRequests)
	}

	close(doneCh)
	for i := 0; i < concurrency; i++ {
		select {
		case err := <-resultCh:
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
		case <-time.After(time.Second):
			t.Fatalf("timeout")
		}
	}

	pendingRequests = c.PendingRequests()
	if pendingRequests != 0 {
		t.Fatalf("non-zero pendingRequests: %d", pendingRequests)
	}
}

var (
	errRespLineNOProtocol   = errors.New("no protocol provided")
	errRespLineNOStatusCode = errors.New("no status code provided")
)

type SimpleRequest struct {
	targetwithport string
}

func (r *SimpleRequest) Method() []byte {
	return []byte("GET")
}

func (r *SimpleRequest) TargetWithPort() string {
	return r.targetwithport
}
func (r *SimpleRequest) SetTargetWithPort(s string) {
	r.targetwithport = s
}

func (r *SimpleRequest) PathWithQueryFragment() []byte {
	return []byte("/")
}

func (r *SimpleRequest) Protocol() []byte {
	return []byte("HTTP/1.1")
}

func (r *SimpleRequest) WriteHeaderTo(w *bufio.Writer) error {
	w.WriteString("Host: www.bing.com\r\nUser-Agent: test client\r\n\r\n")
	return w.Flush()
}

func (r *SimpleRequest) WriteBodyTo(w *bufio.Writer) error {
	return nil
}

func (r *SimpleRequest) ConnectionClose() bool {
	return false
}

func (r *SimpleRequest) IsTLS() bool {
	return false
}

func (r *SimpleRequest) TLSServerName() string {
	return ""
}

func (r *SimpleRequest) GetProxy() *superproxy.SuperProxy {
	return nil
}

func (r *SimpleRequest) GetReadSize() int {
	return 0
}

func (r *SimpleRequest) GetWriteSize() int {
	return 0
}

func (r *SimpleRequest) AddReadSize(n int) {}

func (r *SimpleRequest) AddWriteSize(n int) {}

type SimpleResponse struct {
	size int
	body []byte
}

func (r *SimpleResponse) ReadFrom(discardBody bool, br *bufio.Reader) error {
	b, err := br.ReadBytes('!')
	if err != nil {
		return err
	}
	r.size = len(b)
	r.body = b
	return nil
}

func (r *SimpleResponse) GetBody() []byte {
	return r.body
}

func (r *SimpleResponse) ConnectionClose() bool {
	return false
}

func (r *SimpleResponse) GetSize() int {
	return r.size
}
