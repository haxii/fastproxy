package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"sync"

	"github.com/haxii/fastproxy/http"
	"github.com/haxii/fastproxy/superproxy"
	"github.com/haxii/fastproxy/util"
)

// RequestPool pooling requests
type RequestPool struct{ pool sync.Pool }

// Acquire get a request from pool
func (r *RequestPool) Acquire() *Request {
	v := r.pool.Get()
	if v == nil {
		return &Request{}
	}
	return v.(*Request)
}

// Release put a request back into pool
func (r *RequestPool) Release(req *Request) {
	req.Reset()
	r.pool.Put(req)
}

// ResponsePool pooling responses
type ResponsePool struct{ pool sync.Pool }

// Acquire get a response from pool
func (r *ResponsePool) Acquire() *Response {
	v := r.pool.Get()
	if v == nil {
		return &Response{}
	}
	return v.(*Response)
}

// Release put a response back into pool
func (r *ResponsePool) Release(resp *Response) {
	resp.Reset()
	r.pool.Put(resp)
}

/*
 * implements basic http request & response based on client
 */

// Request http request implementation of http client
type Request struct {
	// reader stores the original raw data of request
	reader *bufio.Reader

	// start line of http request, i.e. request line
	// build from reader
	reqLine http.RequestLine

	// headers info, includes conn close and content length
	header http.Header
	// rawHeader the raw header in bytes to be sent to target, which can be changed by hijacker
	rawHeader []byte
	// originalHeaderLength the header size send by client, before hijacking
	originalHeaderLength int

	// body body parser
	body http.Body

	// hijacker, used for recording the http traffic
	hijacker           Hijacker
	hijackerBodyWriter io.WriteCloser

	// proxy super proxy used for target connection
	proxy *superproxy.SuperProxy

	// TLS request settings
	isTLS         bool
	tlsServerName string
}

// Reset reset request
func (r *Request) Reset() {
	r.reader = nil
	r.reqLine.Reset()
	r.header.Reset()
	r.rawHeader = nil
	r.originalHeaderLength = 0
	r.hijacker = nil
	r.proxy = nil
	r.isTLS = false
	r.tlsServerName = ""
}

// parseStartLine inits request with provided reader
// then parse the start line of the http request
func (r *Request) parseStartLine(reader *bufio.Reader) (int, error) {
	var rn int
	if r.reader != nil {
		return rn, errors.New("request already initialized")
	}

	if reader == nil {
		return rn, errors.New("nil reader provided")
	}
	if err := r.reqLine.Parse(reader); err != nil {
		if err == io.EOF {
			return rn, err
		}
		return rn, util.ErrWrapper(err, "fail to read start line of request")
	}
	rn += len(r.reqLine.GetRequestLine())

	r.reader = reader
	return rn, nil
}

// SetTLS set request as TLS
func (r *Request) SetTLS(tlsServerName string) {
	r.isTLS = true
	r.tlsServerName = tlsServerName
}

// SetHijacker set hijacker for this request
func (r *Request) SetHijacker(h Hijacker) {
	r.hijacker = h
}

// SetProxy set super proxy for this request
func (r *Request) SetProxy(p *superproxy.SuperProxy) {
	r.proxy = p
}

// GetProxy get super proxy for this request
func (r *Request) GetProxy() *superproxy.SuperProxy {
	return r.proxy
}

// Method request method in UPPER case
func (r *Request) Method() []byte {
	return r.reqLine.Method()
}

// TargetWithPort the target IP with port is exists, otherwise the domain with ip
func (r *Request) TargetWithPort() string {
	return r.reqLine.HostInfo().TargetWithPort()
}

// PathWithQueryFragment request path with query and fragment
func (r *Request) PathWithQueryFragment() []byte {
	return r.reqLine.PathWithQueryFragment()
}

// Protocol HTTP/1.0, HTTP/1.1 etc.
func (r *Request) Protocol() []byte {
	return r.reqLine.Protocol()
}

// ErrNilRequestReader no valid request reader provided
var ErrNilRequestReader = errors.New("empty request")

// peekRawHeader peeks raw header from connection
func (r *Request) peekRawHeader() error {
	if r.reader == nil {
		return ErrNilRequestReader
	}

	// parse header info from request
	var err error
	r.originalHeaderLength, err = r.header.ParseHeaderFields(r.reader)
	if err != nil {
		return util.ErrWrapper(err, "fail to parse request http headers")
	}
	var rawHeader []byte
	rawHeader, err = r.reader.Peek(r.originalHeaderLength)
	if err != nil {
		// should NOT have any errors
		return util.ErrWrapper(err, "fail to read raw headers")
	}
	r.rawHeader = rawHeader
	return nil
}

// discardRawHeader discard the raw header after using
func (r *Request) discardRawHeader() error {
	_, err := r.reader.Discard(r.originalHeaderLength)
	return err
}

// PrePare pre-process the request header, hijack the request if available
func (r *Request) PrePare() error {
	if err := r.peekRawHeader(); err != nil {
		return err
	}
	// hijack the request URL and header
	if r.hijacker == nil {
		return nil
	}

	// modify request header and change super proxy if needed
	newPath, newHeader := r.hijacker.BeforeRequest(r.Method(),
		r.reqLine.PathWithQueryFragment(), r.header, r.rawHeader)

	// reset new path
	r.reqLine.ChangePathWithFragment(newPath)

	// header not modified return it
	if newHeader == nil || bytes.Equal(newHeader, r.rawHeader) {
		return nil
	}

	// re-generate the header
	r.header.Reset()
	if newHeaderLen, err := r.header.Parse(newHeader); err != nil {
		return util.ErrWrapper(err, "fail to parse hijacked request http headers")
	} else {
		newHeader = newHeader[:newHeaderLen]
	}
	r.rawHeader = newHeader
	return nil
}

func (r *Request) makeDNSLookUpAndSetSuperProxy(defaultSuperProxy *superproxy.SuperProxy) {
	hijacker := r.hijacker
	if hijacker == nil {
		r.SetProxy(defaultSuperProxy)
		return
	}

	// do a manual DNS look up
	domain := r.reqLine.HostInfo().Domain()
	if len(domain) > 0 {
		ip := hijacker.Resolve()
		r.reqLine.HostInfo().SetIP(ip)
	}

	// set requests proxy
	superProxy := hijacker.SuperProxy()
	r.SetProxy(superProxy)

}

// WriteHeaderTo write raw http request header to http client
// implemented client's request interface
func (r *Request) WriteHeaderTo(writer *bufio.Writer) (int, int, error) {
	if r.reader == nil {
		return 0, 0, ErrNilRequestReader
	}

	// the header only peeks for parsing in `PrePare`, discard it after using
	defer r.discardRawHeader()

	copiedHeaderLen, err := parallelWriteHeader(
		writer,
		func(header []byte) {
			if r.hijacker != nil {
				r.hijackerBodyWriter = r.hijacker.OnRequest(r.reqLine.PathWithQueryFragment(), r.header, header)
			}
		},
		r.rawHeader)
	return r.originalHeaderLength, copiedHeaderLen, err
}

// WriteBodyTo write raw http request body to http client
// implemented client's request interface
func (r *Request) WriteBodyTo(writer *bufio.Writer) (int, error) {
	if r.reader == nil {
		return 0, errors.New("empty request")
	}
	defer func() {
		if r.hijackerBodyWriter != nil {
			r.hijackerBodyWriter.Close()
		}
	}()
	// write the request body (if any)
	return copyBody(&r.header, &r.body, r.reader, writer,
		func(rawBody []byte) {
			if _, err := util.WriteWithValidation(r.hijackerBodyWriter, rawBody); err != nil {
				// TODO: log the sniffer error
			}
		},
	)
}

// ConnectionClose if the request's "Connection" or "Proxy-Connection" header value is set as "close".
// this determines how the client reusing the connections.
// this func. result is only valid after `WriteTo` method is called
func (r *Request) ConnectionClose() bool {
	return r.header.IsConnectionClose() || r.header.IsProxyConnectionClose()
}

// IsTLS is tls requests
func (r *Request) IsTLS() bool {
	return r.isTLS
}

// TLSServerName server name for handshaking
func (r *Request) TLSServerName() string {
	return r.tlsServerName
}

// Response http response implementation of http client
type Response struct {
	writer   *bufio.Writer
	hijacker Hijacker

	// start line of http response, i.e. request line
	// build from reader
	respLine http.ResponseLine

	// headers info, includes conn close and content length
	header http.Header

	// body http body parser
	body http.Body
}

// Reset reset response
func (r *Response) Reset() {
	r.writer = nil
	r.respLine.Reset()
	r.header.Reset()
}

// WriteTo init response with writer which would write to
func (r *Response) WriteTo(writer *bufio.Writer) error {
	if r.writer != nil {
		return errors.New("response already initialized")
	}

	if writer == nil {
		return errors.New("nil writer provided")
	}

	r.writer = writer
	return nil
}

// SetHijacker set hijacker for this response
func (r *Response) SetHijacker(h Hijacker) {
	r.hijacker = h
}

// ReadFrom read data from http response got
func (r *Response) ReadFrom(discardBody bool, reader *bufio.Reader) (int, error) {
	var num, wn int
	var err error
	// write back the start line to writer(i.e. net/connection)
	if err = r.respLine.Parse(reader); err != nil {
		return num, util.ErrWrapper(err, "fail to read start line of response")
	}

	// rebuild  the start line
	respLineBytes := r.respLine.GetResponseLine()
	// write start line
	if wn, err = util.WriteWithValidation(r.writer, respLineBytes); err != nil {
		return num, util.ErrWrapper(err, "fail to write start line of response")
	}
	num += wn

	// read & write the headers
	var hijackerBodyWriter io.WriteCloser
	defer func() {
		if hijackerBodyWriter != nil {
			hijackerBodyWriter.Close()
		}
	}()
	if _, wn, err = copyHeader(&r.header, reader, r.writer,
		func(rawHeader []byte) {
			if r.hijacker != nil {
				hijackerBodyWriter = r.hijacker.OnResponse(
					r.respLine, r.header, rawHeader)
			}
		},
	); err != nil {
		return num, err
	}
	num += wn

	if discardBody {
		return num, nil
	}

	// write the request body (if any)
	wn, err = copyBody(&r.header, &r.body, reader, r.writer,
		func(rawBody []byte) {
			if _, err := util.WriteWithValidation(hijackerBodyWriter, rawBody); err != nil {
				// TODO: log the sniffer error
			}
		},
	)
	num += wn
	return num, err
}

// ConnectionClose if the request's "Connection" header value is set as "Close"
// this determines how the client reusing the connections
func (r *Response) ConnectionClose() bool {
	return false
}

// additionalDst used by copyHeader and copyBody for additional write
type additionalDst func([]byte)

func copyHeader(header *http.Header,
	src *bufio.Reader, dst1 io.Writer, dst2 additionalDst) (int, int, error) {
	// read and write header
	var originalHeaderLen, copiedHeaderLen int
	var err error
	if originalHeaderLen, err = header.ParseHeaderFields(src); err != nil {
		return originalHeaderLen, 0, util.ErrWrapper(err, "fail to parse http headers")
	}
	var rawHeader []byte
	rawHeader, err = src.Peek(originalHeaderLen)
	if err != nil {
		// should NOT have any errors
		return originalHeaderLen, 0, util.ErrWrapper(err, "fail to reader raw headers")
	}
	defer src.Discard(originalHeaderLen)

	copiedHeaderLen, err = parallelWriteHeader(dst1, dst2, rawHeader)
	return originalHeaderLen, copiedHeaderLen, err
}

// parallelWriteBody write body data to dst1 dst2 concurrently
// TODO: @daizong with timeout
func parallelWriteHeader(dst1 io.Writer, dst2 additionalDst, header []byte) (int, error) {
	var wg sync.WaitGroup
	var wn int
	var err error
	wg.Add(2)
	go func() {
		m := 0
		unReadHeader := header
		for {
			unReadHeader = unReadHeader[m:]
			m = bytes.IndexByte(unReadHeader, '\n')
			if m < 0 {
				break
			}
			m++
			headerLine := unReadHeader[:m]
			if !http.IsProxyHeader(headerLine) {
				n, e := util.WriteWithValidation(dst1, headerLine)
				wn += n
				if e != nil {
					err = e
					break
				}
			}

		}
		wg.Done()
	}()
	go func() {
		dst2(header)
		wg.Done()
	}()
	wg.Wait()
	if err != nil {
		return wn, util.ErrWrapper(err, "error occurred when write to dst")
	}
	return wn, nil
}

func copyBody(header *http.Header, body *http.Body,
	src *bufio.Reader, dst1 io.Writer, dst2 additionalDst) (int, error) {
	w := func(isChunkHeader bool, data []byte) (int, error) {
		return parallelWriteBody(dst1, dst2, data)
	}
	return body.Parse(src, header.BodyType(), header.ContentLength(), w)
}

// parallelWriteBody write body data to dst1 dst2 concurrently
// TODO: @daizong with timeout
func parallelWriteBody(dst1 io.Writer, dst2 additionalDst, data []byte) (int, error) {
	var wg sync.WaitGroup
	var wn int
	var err error
	wg.Add(2)
	go func() {
		wn, err = util.WriteWithValidation(dst1, data)
		wg.Done()
	}()
	go func() {
		dst2(data)
		wg.Done()
	}()
	wg.Wait()
	if err != nil {
		return wn, util.ErrWrapper(err, "error occurred when write to dst")
	}
	return wn, nil
}
