package http

import (
	"bufio"
	"errors"
	"io"
	"net"
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
	hostInfo      HostInfo

	//byte size read from reader
	readSize int

	//byte size written to writer
	writeSize int
}

//Reset reset request
func (r *Request) Reset() {
	r.reader = nil
	r.reqLine.Reset()
	r.header.Reset()
	r.hostInfo.Reset()
	r.hijacker = nil
	r.proxy = nil
	r.isTLS = false
	r.tlsServerName = ""
	r.readSize = 0
	r.writeSize = 0
}

// ReadFrom init request with reader
// then parse the start line of the http request
func (r *Request) ReadFrom(reader *bufio.Reader) error {
	if r.reader != nil {
		return errors.New("request already initialized")
	}

	if reader == nil {
		return errors.New("nil reader provided")
	}
	if err := r.reqLine.Parse(reader); err != nil {
		return util.ErrWrapper(err, "fail to read start line of request")
	}
	r.reader = reader
	r.hostInfo.ParseHostWithPort(r.reqLine.HostWithPort())
	return nil
}

//SetTLS set request as TLS
func (r *Request) SetTLS(tlsServerName string) {
	r.isTLS = true
	r.tlsServerName = tlsServerName
}

//SetHijacker set hijacker for this request
func (r *Request) SetHijacker(h hijack.Hijacker) {
	r.hijacker = h
}

//GetHijacker get hijacker for this request
func (r *Request) GetHijacker() hijack.Hijacker {
	return r.hijacker
}

//SetProxy set super proxy for this request
func (r *Request) SetProxy(p *superproxy.SuperProxy) {
	r.proxy = p
}

//GetProxy get super proxy for this request
func (r *Request) GetProxy() *superproxy.SuperProxy {
	return r.proxy
}

//Method request method in UPPER case
func (r *Request) Method() []byte {
	return r.reqLine.Method()
}

//HostInfo returns host info
func (r *Request) HostInfo() *HostInfo {
	return &r.hostInfo
}

//SetHostWithPort set host with port
func (r *Request) SetHostWithPort(hostWithPort string) {
	r.hostInfo.ParseHostWithPort(hostWithPort)
}

//PathWithQueryFragment request path with query and fragment
func (r *Request) PathWithQueryFragment() []byte {
	return r.reqLine.PathWithQueryFragment()
}

//Protocol HTTP/1.0, HTTP/1.1 etc.
func (r *Request) Protocol() []byte {
	return r.reqLine.Protocol()
}

//WriteHeaderTo write raw http request header to http client
//implemented client's request interface
func (r *Request) WriteHeaderTo(writer *bufio.Writer) error {
	if r.reader == nil {
		return errors.New("Empty request, nothing to write")
	}
	//read & write the headers
	rn, err := copyHeader(&r.header, r.reader, writer,
		func(rawHeader []byte) {
			r.writeSize += len(rawHeader)
			r.hijackerBodyWriter = r.hijacker.OnRequest(r.header, rawHeader)
		},
	)

	r.AddReadSize(rn)
	return err
}

//WriteBodyTo write raw http request body to http client
//implemented client's request interface
func (r *Request) WriteBodyTo(writer *bufio.Writer) error {
	if r.reader == nil {
		return errors.New("Empty request, nothing to write")
	}
	//write the request body (if any)
	return copyBody(&r.header, &r.body, r.reader, writer,
		func(rawBody []byte) {
			r.readSize += len(rawBody)
			r.writeSize += len(rawBody)
			if err := util.WriteWithValidation(r.hijackerBodyWriter, rawBody); err != nil {
				//TODO: log the sniffer error
			}
		},
	)
}

// ConnectionClose if the request's "Connection" or "Proxy-Connection" header value is set as "close".
// this determines how the client reusing the connetions.
// this func. result is only valid after `WriteTo` method is called
func (r *Request) ConnectionClose() bool {
	return r.header.IsConnectionClose() || r.header.IsProxyConnectionClose()
}

//IsTLS is tls requests
func (r *Request) IsTLS() bool {
	return r.isTLS
}

//TLSServerName server name for handshaking
func (r *Request) TLSServerName() string {
	return r.tlsServerName
}

//GetReadSize return readSize
func (r *Request) GetReadSize() int {
	return r.readSize
}

// add read size
func (r *Request) AddReadSize(n int) {
	r.readSize += n
}

//GetWriteSize return writeSize
func (r *Request) GetWriteSize() int {
	return r.writeSize
}

//add write size
func (r *Request) AddWriteSize(n int) {
	r.writeSize += n
}

//return reqline byte size
func (r *Request) GetReqLineSize() int {
	return len(r.reqLine.GetRequestLine())
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

	//totol byte size of header and body
	size int
}

//header and body size of per Response
func (r *Response) GetSize() int {
	return r.size
}

//Reset reset response
func (r *Response) Reset() {
	r.writer = nil
	r.respLine.Reset()
	r.header.Reset()
	r.size = 0
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

//SetHijacker set hijacker for this response
func (r *Response) SetHijacker(h hijack.Hijacker) {
	r.hijacker = h
}

//GetHijacker get hijacker for this response
func (r *Response) GetHijacker() hijack.Hijacker {
	return r.hijacker
}

//ReadFrom read data from http response got
func (r *Response) ReadFrom(discardBody bool, reader *bufio.Reader) error {
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
	r.size += len(respLineBytes)

	//read & write the headers
	var hijackerBodyWriter io.Writer
	if _, err := copyHeader(&r.header, reader, r.writer,
		func(rawHeader []byte) {
			r.size += len(rawHeader)
			hijackerBodyWriter = r.hijacker.OnResponse(
				r.respLine, r.header, rawHeader)
		},
	); err != nil {
		return err
	}

	if discardBody {
		return nil
	}

	//write the request body (if any)
	return copyBody(&r.header, &r.body, reader, r.writer,
		func(rawBody []byte) {
			r.size += len(rawBody)
			if err := util.WriteWithValidation(hijackerBodyWriter, rawBody); err != nil {
				//TODO: log the sniffer error
			}
		},
	)
}

//ConnectionClose if the request's "Connection" header value is set as "Close"
//this determines how the client reusing the connetions
func (r *Response) ConnectionClose() bool {
	return false
}

//additionalDst used by copyHeader and copyBody for additional write
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

//parallelWrite write data to dst1 dst2 concurrently
//TODO: with timeout?
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

type HostInfo struct {
	domain       string
	ip           net.IP
	port         string
	hostWithPort string
	//ip with port if ip not nil, else domain with port
	targetWithPort string
}

//Reset reset host info
func (h *HostInfo) Reset() {
	h.domain = ""
	h.ip = nil
	h.port = ""
	h.hostWithPort = ""
	h.targetWithPort = ""
}

//Domain return domain
func (h *HostInfo) Domain() string {
	return h.domain
}

//Port return port
func (h *HostInfo) Port() string {
	return h.port
}

//IP return ip
func (h *HostInfo) IP() net.IP {
	return h.ip
}

//HostWithPort return hostWithPort
func (h *HostInfo) HostWithPort() string {
	return h.hostWithPort
}

//TargetWithPort return targetWithPort
func (h *HostInfo) TargetWithPort() string {
	return h.targetWithPort
}

//ParseHostWithPort parse host with port, and set host, ip, port, hostWithPort, targetWithPort
func (h *HostInfo) ParseHostWithPort(hostWithPort string) {
	host, port, err := net.SplitHostPort(hostWithPort)
	if err != nil {
		return
	}
	ip := net.ParseIP(host)
	if ip != nil {
		h.ip = ip
	} else {
		h.domain = host
	}
	h.port = port
	h.hostWithPort = hostWithPort
	h.targetWithPort = hostWithPort
}

//SetIP set ip and update targetWithPort
func (h *HostInfo) SetIP(ip net.IP) {
	if ip == nil {
		return
	}
	h.ip = ip
	h.targetWithPort = ip.String() + ":" + h.port
}
