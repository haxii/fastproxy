package proxy

import (
	"bufio"
	"errors"
	"io"
	"sync"

	"github.com/haxii/fastproxy/bytebufferpool"
	"github.com/haxii/fastproxy/hijack"
	"github.com/haxii/fastproxy/http"
	"github.com/haxii/fastproxy/superproxy"
	"github.com/haxii/fastproxy/util"
)

/*
 * implements basic http request & response based on client
 */

//Request http request implementation of http client
type Request struct {
	//reader stores the original raw data of request
	reader *bufio.Reader

	//start line of http request, i.e. request line
	//build from reader
	reqLine http.RequestLine

	//headers info, includes conn close and content length
	header http.Header

	//body body parser
	body http.Body

	//hijacker, used for recording the http traffic
	hijacker           hijack.Hijacker
	hijackerBodyWriter io.Writer

	//proxy super proxy used for target connection
	proxy *superproxy.SuperProxy

	//TLS request settings
	isTLS         bool
	tlsServerName string
	hostWithPort  string
}

//Reset reset request
func (r *Request) Reset() {
	r.reader = nil
	r.reqLine.Reset()
	r.header.Reset()
	r.hijacker = nil
	r.proxy = nil
	r.isTLS = false
	r.tlsServerName = ""
	r.hostWithPort = ""
}

// InitWithProxyReader init request with reader
// then parse the start line of the http request
func (r *Request) InitWithProxyReader(reader *bufio.Reader, hijacker hijack.Hijacker) error {
	return r.initWithReader(reader, hijacker, false, "")
}

// InitWithTLSClientReader init request with reader supports TLS connections
func (r *Request) InitWithTLSClientReader(reader *bufio.Reader,
	hijacker hijack.Hijacker, tlsServerName string) error {
	return r.initWithReader(reader, hijacker, true, tlsServerName)
}

func (r *Request) initWithReader(reader *bufio.Reader,
	hijacker hijack.Hijacker, isTLS bool, tlsServerName string) error {
	if r.reader != nil {
		return errors.New("request already initialized")
	}

	if reader == nil {
		return errors.New("nil reader provided")
	}

	if isTLS && len(tlsServerName) == 0 {
		return errors.New("empty tls server name provided")
	}

	if err := r.reqLine.Parse(reader); err != nil {
		return util.ErrWrapper(err, "fail to read start line of request")
	}
	r.reader = reader
	r.hijacker = hijacker
	r.isTLS = isTLS
	r.tlsServerName = tlsServerName
	r.hostWithPort = r.reqLine.HostWithPort()
	return nil
}

//SetProxy set super proxy for this request
func (r *Request) SetProxy(p *superproxy.SuperProxy) {
	r.proxy = p
}

//GetProxy get super proxy for this request
func (r *Request) GetProxy() *superproxy.SuperProxy {
	return r.proxy
}

//StartLine startline of the http request
//implemented client's request interface
func (r *Request) StartLine() []byte {
	return r.reqLine.RebuildRequestLine()
}

//StartLineWithFullURI startline of the http request with full uri
//implemented client's request interface
func (r *Request) StartLineWithFullURI() []byte {
	return r.reqLine.RawRequestLine()
}

//WriteHeaderTo write raw http request header to http client
//implemented client's request interface
func (r *Request) WriteHeaderTo(writer *bufio.Writer) error {
	if r.reader == nil {
		return errors.New("Empty request, nothing to write")
	}
	//read & write the headers
	if err := copyHeader(
		r.reader, writer, &r.header,
		func(rawHeader []byte) {
			r.hijackerBodyWriter = r.hijacker.GetRequestWriter(
				r.hostWithPort, r.reqLine.Method(), r.reqLine.Path(),
				r.header, rawHeader)
		},
	); err != nil {
		return err
	}
	return nil
}

//WriteBodyTo write raw http request body to http client
//implemented client's request interface
func (r *Request) WriteBodyTo(writer *bufio.Writer) error {
	if r.reader == nil {
		return errors.New("Empty request, nothing to write")
	}
	//write the request body (if any)
	return copyBody(&r.body, r.reader, writer, r.hijackerBodyWriter, r.header)
}

// ConnectionClose if the request's "Connection" header value is set as "Close".
// this determines how the client reusing the connetions.
// this func. result is only valid after `WriteTo` method is called
func (r *Request) ConnectionClose() bool {
	return r.header.IsConnectionClose()
}

//IsIdempotent specified in request's start line usually
func (r *Request) IsIdempotent() bool {
	return r.reqLine.IsIdempotent()
}

//IsTLS is tls requests
func (r *Request) IsTLS() bool {
	return r.isTLS
}

//HostWithPort host/addr target
func (r *Request) HostWithPort() string {
	return r.hostWithPort
}

//SetHostWithPort set host with port hardly
func (r *Request) SetHostWithPort(hostWithPort string) {
	r.hostWithPort = hostWithPort
}

//TLSServerName server name for handshaking
func (r *Request) TLSServerName() string {
	return r.tlsServerName
}

//Response http response implementation of http client
type Response struct {
	writer   *bufio.Writer
	hijacker hijack.Hijacker

	//start line of http response, i.e. request line
	//build from reader
	respLine http.ResponseLine

	//headers info, includes conn close and content length
	header http.Header

	//body http body parser
	body http.Body
}

//Reset reset response
func (r *Response) Reset() {
	r.writer = nil
	r.respLine.Reset()
	r.header.Reset()
}

// InitWithWriter init response with writer
func (r *Response) InitWithWriter(writer *bufio.Writer, hijacker hijack.Hijacker) error {
	if r.writer != nil {
		return errors.New("response already initialized")
	}

	if writer == nil {
		return errors.New("nil writer provided")
	}

	r.writer = writer
	r.hijacker = hijacker
	return nil
}

//ReadFrom read data from http response got
func (r *Response) ReadFrom(reader *bufio.Reader) error {
	//write back the start line to writer(i.e. net/connection)
	if err := r.respLine.Parse(reader); err != nil {
		return util.ErrWrapper(err, "fail to read start line of response")
	}

	//rebuild  the start line
	respLineBytes := r.respLine.GetResponseLine()
	//write start line
	if err := util.WriteWithValidation(r.writer, respLineBytes); err != nil {
		return util.ErrWrapper(err, "fail to write start line of response")
	}

	//read & write the headers
	var hijackerBodyWriter io.Writer
	if err := copyHeader(
		reader, r.writer, &r.header,
		func(rawHeader []byte) {
			hijackerBodyWriter = r.hijacker.GetResponseWriter(
				r.respLine.GetStatusCode(),
				r.header, rawHeader)
		},
	); err != nil {
		return err
	}

	//write the request body (if any)
	return copyBody(&r.body, reader, r.writer, hijackerBodyWriter, r.header)
}

//ConnectionClose if the request's "Connection" header value is set as "Close"
//this determines how the client reusing the connetions
func (r *Response) ConnectionClose() bool {
	return false
}

var (
	//pool for requests and responses
	requestPool  sync.Pool
	responsePool sync.Pool
)

// AcquireRequest returns an empty Request instance from request pool.
//
// The returned Request instance may be passed to ReleaseRequest when it is
// no longer needed. This allows Request recycling, reduces GC pressure
// and usually improves performance.
func AcquireRequest() *Request {
	v := requestPool.Get()
	if v == nil {
		return &Request{}
	}
	return v.(*Request)
}

// ReleaseRequest returns req acquired via AcquireRequest to request pool.
//
// It is forbidden accessing req and/or its' members after returning
// it to request pool.
func ReleaseRequest(req *Request) {
	req.Reset()
	requestPool.Put(req)
}

// AcquireResponse returns an empty Response instance from response pool.
//
// The returned Response instance may be passed to ReleaseResponse when it is
// no longer needed. This allows Response recycling, reduces GC pressure
// and usually improves performance.
func AcquireResponse() *Response {
	v := responsePool.Get()
	if v == nil {
		return &Response{}
	}
	return v.(*Response)
}

// ReleaseResponse return resp acquired via AcquireResponse to response pool.
//
// It is forbidden accessing resp and/or its' members after returning
// it to response pool.
func ReleaseResponse(resp *Response) {
	resp.Reset()
	responsePool.Put(resp)
}

func copyHeader(src *bufio.Reader, dst *bufio.Writer,
	header *http.Header, parsedHeaderHandler func(headers []byte)) error {
	//read and write header
	buffer := bytebufferpool.Get()
	defer bytebufferpool.Put(buffer)
	if err := header.ParseHeaderFields(src, buffer); err != nil {
		return util.ErrWrapper(err, "fail to parse http headers")
	}
	if err := util.WriteWithValidation(dst, buffer.B); err != nil {
		return util.ErrWrapper(err, "fail to write http headers")
	}

	parsedHeaderHandler(buffer.B)
	return nil
}

func copyBody(body *http.Body, src *bufio.Reader, dst *bufio.Writer,
	hijackerWriter io.Writer, header http.Header) error {
	isDstSet := dst == nil
	isHijackSet := hijackerWriter == nil
	w := func(isChunkHeader bool, data []byte) error {
		if isDstSet {
			if err := util.WriteWithValidation(dst, data); err != nil {
				return err
			}
		}
		if isHijackSet {
			if err := util.WriteWithValidation(hijackerWriter, data); err != nil {
				return err
			}
		}
		return nil
	}
	return body.Parse(src, header.BodyType(), header.ContentLength(), w)
}
