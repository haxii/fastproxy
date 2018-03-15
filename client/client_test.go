package client

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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

	testClientDoConcurrentWithLargeNumber(t)

	testClientDoIsIdempotent(t)

	testHostClientPendingRequests(t)
	testClientDoWithHTTPSRequest(t)

	testClientDoWithPostRequest(t)
}

func TestClientDoWithBigHeaderOrBody(t *testing.T) {
	go func() {
		nethttp.HandleFunc("/test", func(w nethttp.ResponseWriter, r *nethttp.Request) {
			bodyData := ""
			for i := 0; i < 100000; i++ {
				bodyData += "test"
			}
			bodyData += "!"
			fmt.Fprint(w, bodyData)
		})
		log.Fatal(nethttp.ListenAndServe(":8888", nil))
	}()
	time.Sleep(time.Second)
	testClientDoWithBigHeader(t)
	testClientDoWithBigBodyResponse(t)
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

func testClientDoWithBigHeader(t *testing.T) {
	var err error
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &Client{
		BufioPool: bPool,
	}
	req := &BigHeaderRequest{}
	req.SetTargetWithPort("0.0.0.0:8888")
	resp := &SimpleResponse{}
	err = c.Do(req, resp)
	if err == nil {
		t.Fatalf("unexpected error : %s", io.ErrShortWrite.Error())
	}
}

func testClientDoConcurrentWithLargeNumber(t *testing.T) {
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &Client{
		BufioPool:       bPool,
		MaxConnsPerHost: 50,
	}
	var wg sync.WaitGroup
	resultCh := make(chan error, 51)
	for i := 0; i < 51; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := &SimpleRequest{}
			req.SetTargetWithPort("127.0.0.1:10000")
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
	j := 0
	for i := 0; i < 51; i++ {
		select {
		case err := <-resultCh:
			if err != nil {
				j++
				if j != 1 {
					t.Fatal("unexpected error: one client should have no free connections available to host")
				}
			}
		case <-time.After(time.Second):
			t.Fatalf("timeout")
		}
	}
	wg.Wait()
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
	go func() {
		ln, err := net.Listen("tcp4", "0.0.0.0:8080")
		i := 0
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		nethttp.HandleFunc("/idempotent", func(w nethttp.ResponseWriter, r *nethttp.Request) {
			i++
			if i != 5 {
				conn, _, _ := w.(nethttp.Hijacker).Hijack()
				conn.Close()
			} else {
				fmt.Fprint(w, "Hello world!")
			}
		})
		nethttp.Serve(ln, nil)
	}()
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &Client{
		BufioPool: bPool,
	}
	req := &IdempotentRequest{}
	req.SetMethod([]byte("GET"))
	req.SetTargetWithPort("127.0.0.1:8080")
	req.SetPathWithQueryFragment([]byte("/idempotent"))
	resp := &SimpleResponse{}
	err := c.Do(req, resp)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if resp.GetSize() == 0 {
		t.Fatal("Response can't be empty")
	}
	if !bytes.Contains(resp.GetBody(), []byte("Hello world!")) {
		t.Fatalf("Idempotent test error")
	}
	req.SetMethod([]byte("POST"))
	newResp := &SimpleResponse{}
	err = c.Do(req, newResp)
	if err != ErrConnectionClosed {
		t.Fatalf("expected error: %s", ErrConnectionClosed.Error())
	}
}

func testClientDoWithBigBodyResponse(t *testing.T) {
	var err error
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &Client{
		BufioPool: bPool,
	}
	req := &BigHeaderRequest{}
	req.SetTargetWithPort("0.0.0.0:8888")
	resp := &BigBodyResponse{}
	err = c.Do(req, resp)
	if err == nil {
		t.Fatalf("unexpected error: %s", io.ErrShortWrite.Error())
	}
	if err != io.ErrShortWrite {
		t.Fatalf("unexpected error: %s", err.Error())
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
		})
		log.Fatal(nethttp.ListenAndServe(":9999", nil))
	}()

	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &HostClient{
		BufioPool:   bPool,
		ReadTimeout: 2 * time.Second,
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

func testClientDoWithHTTPSRequest(t *testing.T) {
	go func() {
		nethttp.HandleFunc("/https", func(w nethttp.ResponseWriter, req *nethttp.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("Hello world!"))
		})
		err := nethttp.ListenAndServeTLS(":443", "./certificate/server.crt", "./certificate/server.key", nil)
		if err != nil {
			log.Fatal("ListenAndServe: ", err)
		}
	}()
	var err error
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &Client{
		BufioPool: bPool,
	}
	req := &HTTPSRequest{}
	resp := &SimpleResponse{}
	err = c.Do(req, resp)
	if err != nil {
		t.Fatalf("unexpected error : %s", err.Error())
	}
	if !bytes.Contains(resp.GetBody(), []byte("Hello world!")) {
		t.Fatal("Response body is wrong")
	}
}

func testClientDoWithPostRequest(t *testing.T) {
	var err error
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &Client{
		BufioPool: bPool,
	}
	req := &IdempotentRequest{}
	req.SetMethod([]byte("POST"))
	req.SetTargetWithPort("127.0.0.1:10000")
	req.SetPathWithQueryFragment([]byte("/"))
	resp := &SimpleResponse{}
	err = c.Do(req, resp)
	if err != nil {
		t.Fatalf("unexpected error : %s", err.Error())
	}
	if !bytes.Contains(resp.GetBody(), []byte("Hello world!")) {
		t.Fatal("Response body is wrong")
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

type BigHeaderRequest struct {
	readSize       int
	targetwithport string
}

func (r *BigHeaderRequest) Method() []byte {
	return []byte("GET")
}

func (r *BigHeaderRequest) TargetWithPort() string {
	return r.targetwithport
}
func (r *BigHeaderRequest) SetTargetWithPort(s string) {
	r.targetwithport = s
}

func (r *BigHeaderRequest) PathWithQueryFragment() []byte {
	return []byte("/test")
}

func (r *BigHeaderRequest) Protocol() []byte {
	return []byte("HTTP/1.1")
}

func (r *BigHeaderRequest) WriteHeaderTo(w *bufio.Writer) error {
	result := "Cache:"
	for i := 0; i < 100000; i++ {
		result += "S"
	}
	n, err := w.WriteString("Host: www.bing.com\r\nUser-Agent: test client\r\n" + result + "\r\n\r\n")
	if err != nil {
		return err
	}
	if w.Buffered() < n {
		r.readSize += w.Buffered()
		return io.ErrShortWrite
	}
	r.readSize += n
	return nil
}

func (r *BigHeaderRequest) WriteBodyTo(w *bufio.Writer) error {
	return nil
}

func (r *BigHeaderRequest) ConnectionClose() bool {
	return false
}

func (r *BigHeaderRequest) IsTLS() bool {
	return false
}

func (r *BigHeaderRequest) TLSServerName() string {
	return ""
}

func (r *BigHeaderRequest) GetProxy() *superproxy.SuperProxy {
	return nil
}

func (r *BigHeaderRequest) GetReadSize() int {
	return r.readSize
}

func (r *BigHeaderRequest) GetWriteSize() int {
	return 0
}

func (r *BigHeaderRequest) AddReadSize(n int) {
	r.readSize += n
}

func (r *BigHeaderRequest) AddWriteSize(n int) {
	r.readSize += n
}

type BigBodyResponse struct {
	size int
	body []byte
}

func (r *BigBodyResponse) ReadFrom(discardBody bool, br *bufio.Reader) error {
	b, err := br.ReadBytes('!')
	if err != nil {
		return err
	}
	r.size = len(b)
	r.body = b
	return nil
}

func (r *BigBodyResponse) GetBody() []byte {
	return r.body
}

func (r *BigBodyResponse) ConnectionClose() bool {
	return false
}

func (r *BigBodyResponse) GetSize() int {
	return r.size
}

type IdempotentRequest struct {
	method                []byte
	targetwithport        string
	pathWithQueryFragment []byte
}

func (r *IdempotentRequest) Method() []byte {
	return r.method
}

func (r *IdempotentRequest) SetMethod(method []byte) {
	r.method = method
}
func (r *IdempotentRequest) TargetWithPort() string {
	return r.targetwithport
}
func (r *IdempotentRequest) SetTargetWithPort(s string) {
	r.targetwithport = s
}

func (r *IdempotentRequest) PathWithQueryFragment() []byte {
	return r.pathWithQueryFragment
}

func (r *IdempotentRequest) SetPathWithQueryFragment(p []byte) {
	r.pathWithQueryFragment = p
}

func (r *IdempotentRequest) Protocol() []byte {
	return []byte("HTTP/1.1")
}

func (r *IdempotentRequest) WriteHeaderTo(w *bufio.Writer) error {
	result := "Cache:"
	for i := 0; i < 100000; i++ {
		result += "S"
	}
	_, err := w.WriteString("Host: www.bing.com\r\nUser-Agent: test client\r\n" + result + "\r\n\r\n")
	return err
}

func (r *IdempotentRequest) WriteBodyTo(w *bufio.Writer) error {
	return nil
}

func (r *IdempotentRequest) ConnectionClose() bool {
	return false
}

func (r *IdempotentRequest) IsTLS() bool {
	return false
}

func (r *IdempotentRequest) TLSServerName() string {
	return ""
}

func (r *IdempotentRequest) GetProxy() *superproxy.SuperProxy {
	return nil
}

func (r *IdempotentRequest) GetReadSize() int {
	return 0
}

func (r *IdempotentRequest) GetWriteSize() int {
	return 0
}

func (r *IdempotentRequest) AddReadSize(n int) {
}

func (r *IdempotentRequest) AddWriteSize(n int) {
}

type IdempotentResponse struct {
	size int
	body []byte
}

func (r *IdempotentResponse) ReadFrom(discardBody bool, br *bufio.Reader) error {
	b, err := br.ReadBytes('!')
	if err != nil {
		return err
	}
	r.size = len(b)
	r.body = b
	return nil
}

func (r *IdempotentResponse) GetBody() []byte {
	return r.body
}

func (r *IdempotentResponse) ConnectionClose() bool {
	return false
}

func (r *IdempotentResponse) GetSize() int {
	return r.size
}

type HTTPSRequest struct {
	targetwithport string
}

func (r *HTTPSRequest) Method() []byte {
	return []byte("GET")
}

func (r *HTTPSRequest) TargetWithPort() string {
	return "127.0.0.1:443"
}
func (r *HTTPSRequest) SetTargetWithPort(s string) {}

func (r *HTTPSRequest) PathWithQueryFragment() []byte {
	return []byte("/https")
}

func (r *HTTPSRequest) Protocol() []byte {
	return []byte("HTTP/1.1")
}

func (r *HTTPSRequest) WriteHeaderTo(w *bufio.Writer) error {
	_, err := w.WriteString("Host: www.bing.com\r\nUser-Agent: test client\r\n" + "\r\n")
	return err
}

func (r *HTTPSRequest) WriteBodyTo(w *bufio.Writer) error {
	return nil
}

func (r *HTTPSRequest) ConnectionClose() bool {
	return false
}

func (r *HTTPSRequest) IsTLS() bool {
	return true
}

func (r *HTTPSRequest) TLSServerName() string {
	return ""
}

func (r *HTTPSRequest) GetProxy() *superproxy.SuperProxy {
	return nil
}

func (r *HTTPSRequest) GetReadSize() int {
	return 0
}

func (r *HTTPSRequest) GetWriteSize() int {
	return 0
}

func (r *HTTPSRequest) AddReadSize(n int) {
}

func (r *HTTPSRequest) AddWriteSize(n int) {
}
