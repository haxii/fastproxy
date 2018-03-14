package client

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	nethttp "net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fastfork/fastproxy/http"
	"github.com/fastfork/fastproxy/uri"
	"github.com/fastfork/fastproxy/util"
	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/bytebufferpool"
	proxyhttp "github.com/haxii/fastproxy/proxy/http"
	"github.com/haxii/fastproxy/superproxy"
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
	req := &SimpleRequest{}
	br := bufio.NewReader(strings.NewReader(s))
	err = req.ReadFrom(br)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	req.SetHostWithPort("localhost:10000")
	resp := &SimpleResponse{}
	bf := bytebufferpool.MakeFixedSizeByteBuffer(100)
	bw := bufio.NewWriter(bf)
	err = resp.WriteTo(bw)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	err = c.Do(req, resp)
	if err != nil {
		t.Fatalf("unexpected error : %s", err.Error())
	}
	if resp.GetSize() == 0 {
		t.Fatal("Response can't be empty")
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
		req := &SimpleRequest{}
		br := bufio.NewReader(strings.NewReader(s))
		err = req.ReadFrom(br)
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		req.SetHostWithPort("localhost:10000")
		resp := &SimpleResponse{}
		bf := bytebufferpool.MakeFixedSizeByteBuffer(100)
		bw := bufio.NewWriter(bf)
		err = resp.WriteTo(bw)
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}

		err = c.Do(req, resp)
		if err != nil {
			t.Fatalf("unexpecting error: %s", err.Error())
		}
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

	req := &SimpleRequest{}
	br := bufio.NewReader(strings.NewReader(s))
	err := req.ReadFrom(br)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	resp := &SimpleResponse{}
	bf := bytebufferpool.MakeFixedSizeByteBuffer(100)
	bw := bufio.NewWriter(bf)
	err = resp.WriteTo(bw)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}

	testClientDoWithErrorParamter(t, nil, req, resp, s, errNilBufiopool)
	testClientDoWithErrorParamter(t, bPool, req, resp, errS, errNilTargetHost)

}

func testClientDoWithErrorParamter(t *testing.T, bPool *bufiopool.Pool, req *SimpleRequest, resp *SimpleResponse, s string, expErr error) {
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
		req := &SimpleRequest{}
		br := bufio.NewReader(strings.NewReader(s))
		err = req.ReadFrom(br)
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		req.SetHostWithPort("localhost:10000")
		resp := &SimpleResponse{}
		bf := bytebufferpool.MakeFixedSizeByteBuffer(100)
		bw := bufio.NewWriter(bf)
		err = resp.WriteTo(bw)
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}

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
	req := &SimpleRequest{}
	br := bufio.NewReader(strings.NewReader(s))
	err := req.ReadFrom(br)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	req.SetHostWithPort("localhost:10000")
	resp := &SimpleResponse{}
	byteBuffer := bytebufferpool.MakeFixedSizeByteBuffer(100)
	bw := bufio.NewWriter(byteBuffer)
	err = resp.WriteTo(bw)
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
	resultSize := resp.GetSize()
	for i := 0; i < 10; i++ {
		req := &SimpleRequest{}
		br := bufio.NewReader(strings.NewReader(s))
		err := req.ReadFrom(br)
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		req.SetHostWithPort("localhost:10000")
		resp := &SimpleResponse{}
		byteBuffer := bytebufferpool.MakeFixedSizeByteBuffer(100)
		bw := bufio.NewWriter(byteBuffer)
		err = resp.WriteTo(bw)
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
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
	s := "GET /hellp HTTP/1.1\r\n" +
		"Host: localhost:9999\r\n" +
		"\r\n"
	resultCh := make(chan error, concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			req := &SimpleRequest{}
			br := bufio.NewReader(strings.NewReader(s))
			err := req.ReadFrom(br)
			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}
			req.SetHostWithPort("localhost:9999")
			resp := &SimpleResponse{}
			bf := bytebufferpool.MakeFixedSizeByteBuffer(100)
			bw := bufio.NewWriter(bf)
			err = resp.WriteTo(bw)
			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}
			if err := c.Do(req, resp); err != nil {
				resultCh <- fmt.Errorf("unexpected error: %s", err)
				return
			}

			if resp.GetSize() == 0 {
				resultCh <- fmt.Errorf("Response can't be empty")
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
	fullLine []byte
	method   []byte
	uri      uri.URI
	protocol []byte
	reader   *bufio.Reader
	//headers info, includes conn close and content length
	header http.Header

	//body http body parser
	body  http.Body
	proxy *superproxy.SuperProxy

	//TLS request settings
	isTLS         bool
	tlsServerName string
	hostInfo      proxyhttp.HostInfo

	//byte size read from reader
	readSize int

	//byte size written to writer
	writeSize int
}

func (r *SimpleRequest) Method() []byte {
	return r.method
}
func (r *SimpleRequest) Reset() {
	r.reader = nil
	r.fullLine = r.fullLine[:0]
	r.method = r.method[:0]
	r.uri.Reset()
	r.protocol = r.protocol[:0]
	r.header.Reset()
	r.hostInfo.Reset()
	r.proxy = nil
	r.isTLS = false
	r.tlsServerName = ""
	r.readSize = 0
	r.writeSize = 0
}

// ReadFrom init request with reader
// then parse the start line of the http request
func (r *SimpleRequest) ReadFrom(reader *bufio.Reader) error {
	if r.reader != nil {
		return errors.New("request already initialized")
	}
	if reader == nil {
		return errors.New("nil reader provided")
	}
	if err := r.Parse(reader); err != nil {
		return util.ErrWrapper(err, "fail to read start line of request")
	}

	r.reader = reader
	r.hostInfo.ParseHostWithPort(r.uri.HostWithPort())
	return nil
}

//SetTLS set request as TLS
func (r *SimpleRequest) SetTLS(tlsServerName string) {
	r.isTLS = true
	r.tlsServerName = tlsServerName
}

//SetProxy set super proxy for this request
func (r *SimpleRequest) SetProxy(p *superproxy.SuperProxy) {
	r.proxy = p
}

//GetProxy get super proxy for this request
func (r *SimpleRequest) GetProxy() *superproxy.SuperProxy {
	return r.proxy
}

//HostInfo returns host info
func (r *SimpleRequest) HostInfo() *proxyhttp.HostInfo {
	return &r.hostInfo
}

//SetHostWithPort set host with port
func (r *SimpleRequest) SetHostWithPort(hostWithPort string) {
	r.hostInfo.ParseHostWithPort(hostWithPort)
}

//PathWithQueryFragment request path with query and fragment
func (r *SimpleRequest) PathWithQueryFragment() []byte {
	return r.uri.PathWithQueryFragment()
}

//Protocol HTTP/1.0, HTTP/1.1 etc.
func (r *SimpleRequest) Protocol() []byte {
	return r.protocol
}

//WriteHeaderTo write raw http request header to http client
//implemented client's request interface
func (r *SimpleRequest) WriteHeaderTo(writer *bufio.Writer) error {
	if r.reader == nil {
		return errors.New("Empty request, nothing to write")
	}
	//read & write the headers
	rn, err := copyHeader(&r.header, r.reader, writer,
		func(rawHeader []byte) {
			r.writeSize += len(rawHeader)
		},
	)

	r.AddReadSize(rn)
	return err
}

//WriteBodyTo write raw http request body to http client
//implemented client's request interface
func (r *SimpleRequest) WriteBodyTo(writer *bufio.Writer) error {
	if r.reader == nil {
		return errors.New("Empty request, nothing to write")
	}
	//write the request body (if any)
	return copyBody(&r.header, &r.body, r.reader, writer,
		func(rawBody []byte) {
			r.readSize += len(rawBody)
			r.writeSize += len(rawBody)
		},
	)
}

// ConnectionClose if the request's "Connection" or "Proxy-Connection" header value is set as "close".
// this determines how the client reusing the connetions.
// this func. result is only valid after `WriteTo` method is called
func (r *SimpleRequest) ConnectionClose() bool {
	return false
}

//IsTLS is tls requests
func (r *SimpleRequest) IsTLS() bool {
	return r.isTLS
}

//TLSServerName server name for handshaking
func (r *SimpleRequest) TLSServerName() string {
	return r.tlsServerName
}

//GetReadSize return readSize
func (r *SimpleRequest) GetReadSize() int {
	return r.readSize
}

// add read size
func (r *SimpleRequest) AddReadSize(n int) {
	r.readSize += n
}

//GetWriteSize return writeSize
func (r *SimpleRequest) GetWriteSize() int {
	return r.writeSize
}

//add write size
func (r *SimpleRequest) AddWriteSize(n int) {
	r.writeSize += n
}

type SimpleResponse struct {
	writer *bufio.Writer

	fullLine   []byte
	protocol   []byte
	statusCode int
	statusMsg  []byte

	//headers info, includes conn close and content length
	header http.Header
	//body http body parser
	body http.Body

	size int
}

func (r *SimpleResponse) Reset() {
	r.writer = nil
	r.fullLine = r.fullLine[:0]
	r.protocol = r.protocol[:0]
	r.statusCode = 0
	r.statusMsg = r.statusMsg[:0]
	r.header.Reset()
	r.size = 0
}

func (r *SimpleResponse) ConnectionClose() bool {
	return false
}
func (r *SimpleResponse) GetSize() int {
	return r.size
}

func (r *SimpleResponse) WriteTo(writer *bufio.Writer) error {
	if r.writer != nil {
		return errors.New("response already initialized")
	}

	if writer == nil {
		return errors.New("nil writer provided")
	}

	r.writer = writer
	return nil
}

//ReadFrom read data from http response got
func (r *SimpleResponse) ReadFrom(discardBody bool, reader *bufio.Reader) error {
	//write back the start line to writer(i.e. net/connection)
	if err := r.Parse(reader); err != nil {
		return util.ErrWrapper(err, "fail to read start line of response")
	}

	//rebuild  the start line
	respLineBytes := r.fullLine
	//write start line
	if err := util.WriteWithValidation(r.writer, respLineBytes); err != nil {
		return util.ErrWrapper(err, "fail to write start line of response")
	}
	r.size += len(respLineBytes)

	if discardBody {
		return nil
	}
	return nil
}

func parseStartline(reader *bufio.Reader) ([]byte, error) {
	startLineWithCRLF, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, util.ErrWrapper(err, "fail to read start line")
	}
	if len(startLineWithCRLF) <= 2 {
		return nil, errors.New("not a http start line")
	}
	return startLineWithCRLF, nil
}

func (r *SimpleRequest) Parse(reader *bufio.Reader) error {
	reqLineWithCRLF, err := parseStartline(reader)
	if err != nil {
		return err
	}

	var reqLine []byte
	if reqLineWithCRLF[len(reqLineWithCRLF)-2] == '\r' {
		reqLine = reqLineWithCRLF[:len(reqLineWithCRLF)-2] //CRLF included
	} else {
		reqLine = reqLineWithCRLF[:len(reqLineWithCRLF)-1] //only LF included
	}

	//method token
	methodEndIndex := bytes.IndexByte(reqLine, ' ')
	if methodEndIndex <= 0 {
		return errors.New("no method provided")
	}
	method := reqLine[:methodEndIndex]
	changeToUpperCase(method)

	//request target
	reqURIStartIndex := methodEndIndex + 1
	reqURIEndIndex := reqURIStartIndex + bytes.IndexByte(reqLine[reqURIStartIndex:], ' ')
	if reqURIEndIndex <= reqURIStartIndex {
		return errors.New("no request uri provided")
	}
	reqURI := reqLine[reqURIStartIndex:reqURIEndIndex]
	isConnect := IsMethodConnect(method)
	r.uri.Parse(isConnect, reqURI)

	//protocol
	protocolStartIndex := reqURIEndIndex + 1
	protocol := reqLine[protocolStartIndex:]

	r.fullLine = reqLineWithCRLF
	r.method = method
	r.protocol = protocol

	return nil
}

func (r *SimpleResponse) Parse(reader *bufio.Reader) error {
	respLineWithCRLF, err := parseStartline(reader)
	if err != nil {
		return err
	}

	var respLine []byte
	if respLineWithCRLF[len(respLineWithCRLF)-2] == '\r' {
		respLine = respLineWithCRLF[:len(respLineWithCRLF)-2] //CRLF included
	} else {
		respLine = respLineWithCRLF[:len(respLineWithCRLF)-1] //only LF included
	}

	//http version token
	protocolEndIndex := bytes.IndexByte(respLine, ' ')
	if protocolEndIndex <= 0 {
		return errRespLineNOProtocol
	}
	r.protocol = respLine[:protocolEndIndex]

	//3-digit status code
	statusCodeStartIndex := protocolEndIndex + 1
	statusCodeEndIndex := statusCodeStartIndex + bytes.IndexByte(respLine[statusCodeStartIndex:], ' ')
	if statusCodeEndIndex <= statusCodeStartIndex {
		return errRespLineNOStatusCode
	}
	statusCode := respLine[statusCodeStartIndex:statusCodeEndIndex]
	if code, err := strconv.Atoi(string(statusCode)); code > 0 && err == nil {
		r.statusCode = code
		r.fullLine = respLineWithCRLF
	} else {
		return util.ErrWrapper(err, "fail to parse status status code %s", statusCode)
	}
	r.statusMsg = respLine[statusCodeEndIndex+1:]
	return nil
}

var methodConnect = []byte("CONNECT")

func IsMethodConnect(method []byte) bool {
	return bytes.Equal(method, methodConnect)
}

func changeToUpperCase(s []byte) {
	for i, b := range s {
		if 'a' <= b && b <= 'z' {
			b -= 'a' - 'A'
			s[i] = b
		}
	}
}

type additionalDst func([]byte)

func copyHeader(header *http.Header,
	src *bufio.Reader, dst1 io.Writer, dst2 additionalDst) (int, error) {
	//read and write header
	buffer := bytebufferpool.Get()
	defer bytebufferpool.Put(buffer)
	var rn int
	var err error
	if rn, err = header.ParseHeaderFields(src, buffer); err != nil {
		return rn, util.ErrWrapper(err, "fail to parse http headers")
	}
	return rn, parallelWrite(dst1, dst2, buffer.B)
}

func copyBody(header *http.Header, body *http.Body,
	src *bufio.Reader, dst1 io.Writer, dst2 additionalDst) error {
	w := func(isChunkHeader bool, data []byte) error {
		return parallelWrite(dst1, dst2, data)
	}
	return body.Parse(src, header.BodyType(), header.ContentLength(), w)
}

func parallelWrite(dst1 io.Writer, dst2 additionalDst, data []byte) error {
	var wg sync.WaitGroup
	var err error
	wg.Add(2)
	go func() {
		err = util.WriteWithValidation(dst1, data)
		wg.Done()
	}()
	go func() {
		dst2(data)
		wg.Done()
	}()
	wg.Wait()
	if err != nil {
		return util.ErrWrapper(err, "error occurred when write to dst")
	}
	return nil
}
