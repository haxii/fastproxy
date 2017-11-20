package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"

	"github.com/haxii/fastproxy/bytebufferpool"
	"github.com/haxii/fastproxy/client"
	"github.com/haxii/fastproxy/header"
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
	reqLine header.RequestLine

	//headers info, includes conn close and content length
	header header.Header

	//sniffer, used for recording the http traffic
	sniffer       Sniffer
	snifferWriter io.Writer

	//proxy super proxy used for target connection
	proxy *client.SuperProxy

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
	r.sniffer = nil
	r.proxy = nil
	r.isTLS = false
	r.tlsServerName = ""
	r.hostWithPort = ""
}

// InitWithProxyReader init request with reader
// then parse the start line of the http request
func (r *Request) InitWithProxyReader(reader *bufio.Reader, sniffer Sniffer) error {
	return r.initWithReader(reader, sniffer, false, "")
}

// InitWithTLSClientReader init request with reader supports TLS connections
func (r *Request) InitWithTLSClientReader(reader *bufio.Reader,
	sniffer Sniffer, tlsServerName string) error {
	return r.initWithReader(reader, sniffer, true, tlsServerName)
}

func (r *Request) initWithReader(reader *bufio.Reader,
	sniffer Sniffer, isTLS bool, tlsServerName string) error {
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
	r.sniffer = sniffer
	r.isTLS = isTLS
	r.tlsServerName = tlsServerName
	r.hostWithPort = r.reqLine.HostWithPort()
	return nil
}

//SetProxy set super proxy for this request
func (r *Request) SetProxy(p *client.SuperProxy) {
	r.proxy = p
}

//GetProxy get super proxy for this request
func (r *Request) GetProxy() *client.SuperProxy {
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
			r.snifferWriter = r.sniffer.GetRequestWriter(r.reqLine.RawURI(), r.header)
			if r.snifferWriter != nil {
				r.snifferWriter.Write(r.reqLine.RawRequestLine())
				r.snifferWriter.Write(rawHeader)
			}
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
	return copyBody(r.reader, writer, r.snifferWriter, r.header)
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
	writer  *bufio.Writer
	sniffer Sniffer

	//start line of http response, i.e. request line
	//build from reader
	respLine header.ResponseLine

	//headers info, includes conn close and content length
	header header.Header
}

//Reset reset response
func (r *Response) Reset() {
	r.writer = nil
	r.respLine.Reset()
	r.header.Reset()
}

// InitWithWriter init response with writer
func (r *Response) InitWithWriter(writer *bufio.Writer, sniffer Sniffer) error {
	if r.writer != nil {
		return errors.New("response already initialized")
	}

	if writer == nil {
		return errors.New("nil writer provided")
	}

	r.writer = writer
	r.sniffer = sniffer
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
	var snifferWriter io.Writer
	if err := copyHeader(
		reader, r.writer, &r.header,
		func(rawHeader []byte) {
			snifferWriter = r.sniffer.GetResponseWriter(r.respLine.GetStatusCode(), r.header)
			if snifferWriter != nil {
				snifferWriter.Write(respLineBytes)
				snifferWriter.Write(rawHeader)
			}
		},
	); err != nil {
		return err
	}

	//write the request body (if any)
	return copyBody(reader, r.writer, snifferWriter, r.header)
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
	header *header.Header, parsedHeaderHandler func(headers []byte)) error {
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

func copyBody(src *bufio.Reader, dst *bufio.Writer, snifferWriter io.Writer, header header.Header) error {
	if header.ContentLength() > 0 {
		//read contentLength data more from reader
		return copyBodyFixedSize(src, dst, snifferWriter, header.ContentLength())
	} else if header.IsBodyChunked() {
		//read data chunked
		buffer := bytebufferpool.Get()
		defer bytebufferpool.Put(buffer)
		return copyBodyChunked(src, dst, snifferWriter, buffer)
	} else if header.IsBodyIdentity() {
		//read till eof
		return copyBodyIdentity(src, dst, snifferWriter)
	}
	return nil
}

func copyBodyFixedSize(src *bufio.Reader, dst *bufio.Writer,
	snifferWriter io.Writer, contentLength int64) error {
	byteStillNeeded := contentLength
	for {
		//read one more bytes
		if b, _ := src.Peek(1); len(b) == 0 {
			return io.EOF
		}

		//must read buffed bytes
		b := util.PeekBuffered(src)

		//write read bytes into dst
		_bytesShouldRead := int64(len(b))
		if byteStillNeeded <= _bytesShouldRead {
			_bytesShouldRead = byteStillNeeded
		}
		byteStillNeeded -= _bytesShouldRead
		bytesShouldRead := int(_bytesShouldRead)

		if err := util.WriteWithValidation(dst, b[:bytesShouldRead]); err != nil {
			return util.ErrWrapper(err, "fail to write request body")
		}

		if snifferWriter != nil {
			snifferWriter.Write(b[:bytesShouldRead])
		}

		//discard wrote bytes
		if _, err := src.Discard(bytesShouldRead); err != nil {
			return util.ErrWrapper(err, "fail to write request body")
		}

		//test if still read more bytes
		if byteStillNeeded == 0 {
			return nil
		}
	}
}

var strCRLF = []byte("\r\n")

func copyBodyChunked(src *bufio.Reader, dst *bufio.Writer,
	snifferWriter io.Writer, buffer *bytebufferpool.ByteBuffer) error {
	strCRLFLen := len(strCRLF)

	for {
		//read and calculate chunk size
		buffer.Reset()
		chunkSize, err := parseChunkSize(src, buffer)
		if err != nil {
			return err
		}
		if err := util.WriteWithValidation(dst, buffer.B); err != nil {
			return err
		}

		if snifferWriter != nil {
			snifferWriter.Write(buffer.B)
		}

		//copy the chunk
		if err := copyBodyFixedSize(src, dst, snifferWriter,
			int64(chunkSize+strCRLFLen)); err != nil {
			return err
		}
		if chunkSize == 0 {
			return nil
		}
	}
}

func parseChunkSize(r *bufio.Reader, buffer *bytebufferpool.ByteBuffer) (int, error) {
	n, err := readHexInt(r, buffer)
	if err != nil {
		return -1, err
	}
	c, err := r.ReadByte()
	if err != nil {
		return -1, fmt.Errorf("cannot read '\r' char at the end of chunk size: %s", err)
	}
	if c != '\r' {
		return -1, fmt.Errorf("unexpected char %q at the end of chunk size. Expected %q", c, '\r')
	}
	c, err = r.ReadByte()
	if err != nil {
		return -1, fmt.Errorf("cannot read '\n' char at the end of chunk size: %s", err)
	}
	if c != '\n' {
		return -1, fmt.Errorf("unexpected char %q at the end of chunk size. Expected %q", c, '\n')
	}
	if _, e := buffer.Write([]byte("\r\n")); e != nil {
		return -1, e
	}
	return n, nil
}
func copyBodyIdentity(src *bufio.Reader, dst *bufio.Writer, snifferWriter io.Writer) error {
	if err := copyBodyFixedSize(src, dst, snifferWriter, math.MaxInt64); err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}
	return nil
}
