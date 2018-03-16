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
	"os"
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

	testClientDoTimeoutErrorConcurrent(t)

	testClientDoConcurrentWithLargeNumber(t)

	testClientDoIsIdempotent(t)

	testHostClientPendingRequests(t)

	testClientDoWithHTTPSRequest(t)

	testClientDoWithPostRequest(t)

	testClientDoWithSameConnectionGetMethod(t)

	testClientDoWithSameConnectionPostMethod(t)
}

// Test Client do with big header or big body
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

//test client do with default paramters
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

// test client do with big header
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

// test client do with 51 concurrent but default is 50 expected one error
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

// test client do 50 concurrent
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

// test client do with timeout can be success
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

// test client do with 1000 concurrent will timeout
func testClientDoTimeoutErrorConcurrent(t *testing.T) {
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

// test client do with wrong paramters
func testClientDoWithErrorParamters(t *testing.T) {
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)

	req := &SimpleRequest{}
	resp := &SimpleResponse{}

	testClientDoWithErrorParamter(t, nil, req, resp, errNilBufiopool)
	testClientDoWithErrorParamter(t, bPool, req, resp, errNilTargetHost)

}

// test client do with error paramters
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

// test client do with nil request or response
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

// test client do timeout paramter will get timeout
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

// test client do is idempotent
func testClientDoIsIdempotent(t *testing.T) {
	go func() {
		ln, err := net.Listen("tcp4", "0.0.0.0:8080")
		i := 0
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		nethttp.HandleFunc("/idempotent", func(w nethttp.ResponseWriter, r *nethttp.Request) {
			i++
			if i < 5 {
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
}

// test client do with big response body
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

// test host client pending requests
func testHostClientPendingRequests(t *testing.T) {
	concurrency := 3
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
		BufioPool: bPool,
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

// test client do with https request
func testClientDoWithHTTPSRequest(t *testing.T) {
	go func() {
		nethttp.HandleFunc("/https", func(w nethttp.ResponseWriter, req *nethttp.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("Hello world!"))
		})
		serverCrt := `-----BEGIN CERTIFICATE-----
MIICnzCCAggCCQDbF8N9hzgLKTANBgkqhkiG9w0BAQUFADCBkzELMAkGA1UEBhMC
c2gxGjAYBgNVBAgMEXNoYW5naGFpIGluIENoaW5hMREwDwYDVQQHDAhzaGFuZ2hh
aTEOMAwGA1UECgwFaGF4aWkxEDAOBgNVBAsMB3NlY3Rpb24xEjAQBgNVBAMMCWxv
Y2FsaG9zdDEfMB0GCSqGSIb3DQEJARYQNDkzODg1NTk3QHFxLmNvbTAeFw0xODAz
MDEwMzU4NDRaFw0xODAzMzEwMzU4NDRaMIGTMQswCQYDVQQGEwJzaDEaMBgGA1UE
CAwRc2hhbmdoYWkgaW4gY2hpbmExETAPBgNVBAcMCHNoYW5naGFpMQ4wDAYDVQQK
DAVoYXhpaTEQMA4GA1UECwwHc2VjdGlvbjESMBAGA1UEAwwJbG9jYWxob3N0MR8w
HQYJKoZIhvcNAQkBFhA0OTM4ODU1OTdAcXEuY29tMIGfMA0GCSqGSIb3DQEBAQUA
A4GNADCBiQKBgQCpavxAydg6qDcSHhzwcebD5v/o2yItY1a6cA8t4cd+8661TAQr
//YRISpIwUZ7TOLVdmnMuyUzxGABZQ5iwiKDqbl5GLxB/f3NRWv5Cr8vT4izFNP0
toIky5oEkDq/xBZvVnshBO6fpx1vulnow+3Y3WeriwVXvuQAQw5N8qod/QIDAQAB
MA0GCSqGSIb3DQEBBQUAA4GBAG45K4B2N8lEeCimTyYuS9yGRQINMfdZksL2aDyq
OL95JiCMKM1iFulom/fth3oxi1w95VRFaM4tO8qIBtKuFyWs8x1MMpTJlEamHFTe
H1Id2JuKgDgi4AmxfKPjh+j+U6iNbMgjwo6scfaWcpteGK0FA5jn4cmMmlwhkjCA
L/ib
-----END CERTIFICATE-----
`
		serverKey := `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCpavxAydg6qDcSHhzwcebD5v/o2yItY1a6cA8t4cd+8661TAQr
//YRISpIwUZ7TOLVdmnMuyUzxGABZQ5iwiKDqbl5GLxB/f3NRWv5Cr8vT4izFNP0
toIky5oEkDq/xBZvVnshBO6fpx1vulnow+3Y3WeriwVXvuQAQw5N8qod/QIDAQAB
AoGAdoPnDxOkdfQzAjOanwGvIyA3qZeSIxo5E5dMpxYozsB9WUpiKL2YT4dZ4yeB
vMOecyGxBY1tivc3CgK9u4x/Q2RWQqG4n6d++RKKWEk5Znvi5H35gOcWbQgnOLfe
VJKonqZwhDxWBjlIdKHRdlMY2qXY0rftDthas2zfLIWmSmkCQQDSX5zFhN1U3dAo
cni5Qx3zBCGGw8aoFAH4bUPuvtb7LTnDb+xJDcxhC9pIy+5e3PcSa7cVN0DJpXEo
QPMHp8jHAkEAziluenyR98PoJ2W/D8Cphuc5FvsRXOkGrcLdj397BZzTQhTrEPEr
/qhn2uC4PqGBuS+GV1zgjTf4ocAz7TGHGwJBAKQ7pm0A07V8URQygZLIFepxMCdA
UadHr14dFyqca8K9RNoRV1qU3hhpI2kvY5FFWdFUrCJw9zA060kso043q2MCQQCN
bdDTiGeeoC+/70XeKZ5i5Ha+tCgaI+YoB/l0utCLbiVjPPRxn/E9dwwgFG9wz90t
TFQN1LJbTp1rYW599q8nAkBDbXVZIDjwuL0SyUgnGJUKMILk0aanNE2E885wyuZm
PAnrpRqdDz9eQITxrUgW8vJKxBH6hNNGcMz9VHUgnsSE
-----END RSA PRIVATE KEY-----
`
		f, err := os.Create(".server.crt")
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		f.Write([]byte(serverCrt))
		f.Close()

		f, err = os.Create(".server.key")
		f.Write([]byte(serverKey))
		f.Close()

		err = nethttp.ListenAndServeTLS(":443", ".server.crt", ".server.key", nil)
		if err != nil {
			log.Fatal("ListenAndServe: ", err)
		}
	}()
	time.Sleep(time.Second)
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

// test client do with get method at first and then post method
func testClientDoWithSameConnectionPostMethod(t *testing.T) {
	go func() {
		ln, err := net.Listen("tcp4", "0.0.0.0:10002")
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		i := 0
		nethttp.HandleFunc("/closetest", func(w nethttp.ResponseWriter, r *nethttp.Request) {
			if i > 0 && i < 6 {
				conn, _, _ := w.(nethttp.Hijacker).Hijack()
				conn.Close()
			} else {
				conn, _, _ := w.(nethttp.Hijacker).Hijack()
				conn.Write([]byte("Connection will close!"))
				conn.Close()
			}
			if i == 1 {
				if r.Method != "POST" {
					t.Fatalf("POST Failure")
				}
			}
			i++
		})
		nethttp.Serve(ln, nil)
	}()
	var err error
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &Client{
		BufioPool: bPool,
	}
	req := &IdempotentRequest{}
	req.SetMethod([]byte("GET"))
	req.SetTargetWithPort("127.0.0.1:10002")
	req.SetPathWithQueryFragment([]byte("/closetest"))
	resp := &SimpleResponse{}
	err = c.Do(req, resp)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err.Error())
	}
	if !bytes.Contains(resp.GetBody(), []byte("Connection will close!")) {
		t.Fatalf("Connection closed by peer, Client can't get any data")
	}
	req.SetMethod([]byte("POST"))
	err = c.Do(req, resp)
	if err == nil {
		t.Fatalf("expected error: %s", ErrConnectionClosed)
	}
	if err != ErrConnectionClosed {
		t.Fatalf("expected error: %s, but unexpected error: %s", ErrConnectionClosed, err)
	}
}

// test client do with post request
func testClientDoWithPostRequest(t *testing.T) {
	go func() {
		ln, err := net.Listen("tcp4", "0.0.0.0:10003")
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		nethttp.HandleFunc("/post", func(w nethttp.ResponseWriter, r *nethttp.Request) {
			if r.Method != "POST" {
				t.Fatalf("method is %s", r.Method)
			}
			conn, _, _ := w.(nethttp.Hijacker).Hijack()
			conn.Write([]byte("Post success!"))
			conn.Close()
		})
		nethttp.Serve(ln, nil)
	}()
	time.Sleep(time.Second)
	var err error
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &Client{
		BufioPool: bPool,
	}
	req := &IdempotentRequest{}
	req.SetMethod([]byte("POST"))
	req.SetTargetWithPort("127.0.0.1:10003")
	req.SetPathWithQueryFragment([]byte("/post"))
	resp := &SimpleResponse{}
	err = c.Do(req, resp)
	if err != nil {
		t.Fatalf("unexpected error : %s", err.Error())
	}
	if !bytes.Contains(resp.GetBody(), []byte("Post success!")) {
		t.Fatal("Response body is wrong")
	}
}

// test client do with same connection using get method
func testClientDoWithSameConnectionGetMethod(t *testing.T) {
	go func() {
		ln, err := net.Listen("tcp4", "0.0.0.0:10001")
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		i := 0
		nethttp.HandleFunc("/close", func(w nethttp.ResponseWriter, r *nethttp.Request) {
			if i < 1 {
				conn, _, _ := w.(nethttp.Hijacker).Hijack()
				conn.Write([]byte("Connection will close!"))
				conn.Close()
				i++
			} else {
				fmt.Fprintf(w, "Hello world!")
			}
		})
		nethttp.Serve(ln, nil)
	}()
	var err error
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &Client{
		BufioPool: bPool,
	}
	req := &IdempotentRequest{}
	req.SetMethod([]byte("GET"))
	req.SetTargetWithPort("127.0.0.1:10001")
	req.SetPathWithQueryFragment([]byte("/close"))
	resp := &SimpleResponse{}
	for i := 0; i < 2; i++ {
		err = c.Do(req, resp)
		if err != nil {
			t.Fatalf("Unexpected error: %s", err.Error())
		}
		if i == 0 {
			if !bytes.Contains(resp.GetBody(), []byte("Connection will close!")) {
				t.Fatalf("Connection closed by peer, Client can't get any data")
			}
		} else {
			if !bytes.Contains(resp.GetBody(), []byte("Hello world!")) {
				t.Fatalf("Connection closed by peer, Client can't get any data")
			}
		}
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
	body                  []byte
}

func (r *IdempotentRequest) Method() []byte {
	return r.method
}
func (r *IdempotentRequest) SetBody(b []byte) {
	r.body = b
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
	_, err := w.WriteString("Host: www.bing.com\r\nUser-Agent: test client" + "\r\n\r\n")
	return err
}

func (r *IdempotentRequest) WriteBodyTo(w *bufio.Writer) error {
	_, err := w.WriteString("username=Hello server!\r\n\r\n")
	return err
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
