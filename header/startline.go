package header

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func parseStartline(reader *bufio.Reader) ([]byte, error) {
	startLineWithCRLF, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("fail to read start line with error %s", err)
	}
	if len(startLineWithCRLF) <= 2 {
		return nil, errors.New("not a http start line")
	}
	return startLineWithCRLF, nil
}

//ResponseLine start line of a http response
type ResponseLine struct {
	fullLine   []byte
	statusCode int
}

//GetResponseLine get full response line
func (l *ResponseLine) GetResponseLine() []byte {
	return l.fullLine
}

//GetStatusCode get response status code
func (l *ResponseLine) GetStatusCode() int {
	return l.statusCode
}

//Reset reset response line
func (l *ResponseLine) Reset() {
	l.statusCode = 0
	l.fullLine = l.fullLine[:0]
}

// Parse parse response line
// The first line of a response message is the status-line, consisting
// of the protocol version, a space (SP), the status code, another
// space, a possibly empty textual phrase describing the status code,
// and ending with CRLF.
//
// status-line = HTTP-version SP status-code SP reason-phrase CRLF
// The status-code element is a 3-digit integer code describing the
// result of the server's attempt to understand and satisfy the client's
// corresponding request
func (l *ResponseLine) Parse(reader *bufio.Reader) error {
	respLineWithCRLF, err := parseStartline(reader)
	if err != nil {
		return err
	}

	//http version token
	httpVersionIndex := bytes.IndexByte(respLineWithCRLF, ' ')
	if httpVersionIndex <= 0 {
		return errors.New("no http version provided")
	}

	//3-digit status code
	statusCodeStartIndex := httpVersionIndex + 1
	statusCodeEndIndex := statusCodeStartIndex + bytes.IndexByte(respLineWithCRLF[statusCodeStartIndex:], ' ')
	if statusCodeEndIndex <= statusCodeStartIndex {
		return errors.New("no status code provided")
	}
	statusCode := respLineWithCRLF[statusCodeStartIndex:statusCodeEndIndex]
	if code, err := strconv.Atoi(string(statusCode)); code > 0 && err == nil {
		l.statusCode = code
		l.fullLine = respLineWithCRLF
	} else {
		return fmt.Errorf("fail to parse status code %s with error %s", statusCode, err)
	}

	return nil
}

//RequestLine start line of a http request
type RequestLine struct {
	fullLine []byte
	method   []byte
	uri      requestURI
	protocol []byte
}

//requestURI a uri struct
type requestURI struct {
	rawURI []byte
	scheme []byte
	host   []byte
	path   []byte

	hostWithPort string
}

var (
	methodConnect = []byte("CONNECT")
	methodGet     = []byte("GET")
	methodHead    = []byte("HEAD")
	methodPut     = []byte("PUT")
	methodDelete  = []byte("DELETE")
	methodPost    = []byte("POST")
)

// ParseRequestLine parse request line in stand-alone mode
func ParseRequestLine(reader *bufio.Reader, hostWithPort string) (*RequestLine, error) {
	reqLine := &RequestLine{}

	if err := reqLine.Parse(reader, hostWithPort); err != nil {
		return nil, err
	}
	return reqLine, nil
}

// Parse parse request line,
// hostWithPort can be nil if the startline contains the host,
// i.e. the proxy request, otherwise it will return a `ErrNoHostProvided` error
//
// A request-line begins with a method token, followed by a single space
// (SP), the request-target, another single space (SP), the protocol
// version, and ends with CRLF.
func (l *RequestLine) Parse(reader *bufio.Reader, hostWithPort string) error {
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
	isConnect := bytes.Equal(methodConnect, method)
	l.uri.parse(isConnect, reqURI)
	if err := l.uri.fillHostWithPort(hostWithPort, isConnect); err != nil {
		l.uri.Reset()
		return ErrNoHostProvided
	}

	//protocol
	protocolStartIndex := reqURIEndIndex + 1
	protocol := reqLine[protocolStartIndex:]

	l.fullLine = reqLine
	l.method = method
	l.protocol = protocol

	return nil
}

//Reset reset request line to nil
func (l *RequestLine) Reset() {
	l.fullLine = l.fullLine[:0]
	l.method = l.method[:0]
	l.uri.Reset()
	l.protocol = l.protocol[:0]
}

//IsConnect if the request is a https proxy request
func (l *RequestLine) IsConnect() bool {
	return bytes.Equal(l.method, methodConnect)
}

//IsIdempotent idempotent methods: get, head, put
func (l *RequestLine) IsIdempotent() bool {
	return bytes.Equal(l.method, methodGet) ||
		bytes.Equal(l.method, methodHead) ||
		bytes.Equal(l.method, methodDelete) ||
		bytes.Equal(l.method, methodPut)
}

//HostWithPort the host with port
func (l *RequestLine) HostWithPort() string {
	return l.uri.hostWithPort
}

//RawURI the raw URI separated
func (l *RequestLine) RawURI() []byte {
	return l.uri.rawURI
}

var (
	sp   = []byte(" ")
	crlf = []byte("\r\n")
)

//RebuildRequestLine rebuild the request host line for direct http request
func (l *RequestLine) RebuildRequestLine() []byte {
	reqLine := make([]byte, len(l.method)+len(sp)+
		len(l.uri.path)+len(sp)+len(l.protocol)+len(crlf))
	copyIndex := 0
	copy(reqLine[copyIndex:], l.method)
	copyIndex += len(l.method)
	copy(reqLine[copyIndex:], sp)
	copyIndex += len(sp)
	copy(reqLine[copyIndex:], l.uri.path)
	copyIndex += len(l.uri.path)
	copy(reqLine[copyIndex:], sp)
	copyIndex += len(sp)
	copy(reqLine[copyIndex:], l.protocol)
	copyIndex += len(l.protocol)
	copy(reqLine[copyIndex:], crlf)
	copyIndex += len(crlf)
	return reqLine
}

//parse parse the request URI
//uri1: www.example.com:443
//uri2: /path/to/resource
//uri3.1: http://www.example.com
//uri3.2: http://www.example.com/path/to/resource
func (uri *requestURI) parse(isConnect bool, reqURI []byte) {
	uri.rawURI = reqURI
	//uri1: https proxy reqest's hosts in the request uri
	if isConnect {
		uri.host = reqURI
		return
	}

	//scheme
	schemeEnd := bytes.Index(reqURI, []byte("//"))
	if schemeEnd <= 0 {
		//uri2: not a full uri, only relative path
		uri.path = reqURI
		return
	}
	uri.scheme = reqURI[:schemeEnd]

	//host
	hostNameStart := schemeEnd + 2
	hostNameEnd := hostNameStart + bytes.IndexByte(reqURI[hostNameStart:], '/')
	if hostNameEnd <= hostNameStart {
		//uri3.1
		uri.host = reqURI[hostNameStart:]
		uri.path = []byte{'/'}
	} else {
		//uri3.2
		uri.host = reqURI[hostNameStart:hostNameEnd]
		uri.path = reqURI[hostNameEnd:]
	}
}

func (uri *requestURI) Reset() {
	uri.host = uri.host[:0]
	uri.hostWithPort = ""
	uri.path = uri.path[:0]
	uri.scheme = uri.scheme[:0]
}

//ErrNoHostProvided no host provided in the incoming request
var ErrNoHostProvided = errors.New("no host provided")

func (uri *requestURI) fillHostWithPort(hostWithPort string, isConnect bool) error {
	hasPortFuncByte := func(host []byte) bool {
		return bytes.LastIndexByte(host, ':') >
			bytes.LastIndexByte(host, ']')
	}
	hasPortFuncStr := func(host string) bool {
		return strings.LastIndexByte(host, ':') >
			strings.LastIndexByte(host, ']')
	}
	if len(hostWithPort) > 0 {
		if hasPortFuncStr(hostWithPort) {
			uri.hostWithPort = strings.Repeat(hostWithPort, 1)
			return nil
		}
		return ErrNoHostProvided
	}
	if len(uri.host) == 0 {
		return ErrNoHostProvided
	}
	uri.hostWithPort = string(uri.host)
	if !hasPortFuncByte(uri.host) {
		if isConnect {
			uri.hostWithPort += ":443"
		} else {
			uri.hostWithPort += ":80"
		}
	}
	return nil
}
