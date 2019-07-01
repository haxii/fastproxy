package http

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strconv"

	"github.com/haxii/fastproxy/uri"
	"github.com/haxii/fastproxy/util"
)

// ResponseLine start line of a http response
type ResponseLine struct {
	fullLine   []byte
	protocol   []byte
	statusCode int
	statusMsg  []byte
}

// GetResponseLine get full response line
func (l *ResponseLine) GetResponseLine() []byte {
	return l.fullLine
}

// GetProtocol get response protocol i.e. http version
func (l *ResponseLine) GetProtocol() []byte {
	return l.protocol
}

// GetStatusCode get response status code
func (l *ResponseLine) GetStatusCode() int {
	return l.statusCode
}

// GetStatusMessage get response status message
func (l *ResponseLine) GetStatusMessage() []byte {
	return l.statusMsg
}

// Reset reset response line
func (l *ResponseLine) Reset() {
	l.fullLine = l.fullLine[:0]
	l.protocol = l.protocol[:0]
	l.statusCode = 0
	l.statusMsg = l.statusMsg[:0]
}

var (
	errRespLineNOProtocol   = errors.New("no protocol provided")
	errRespLineNOStatusCode = errors.New("no status code provided")
)

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
	respLineWithCRLF, err := parseStartLine(reader)
	if err != nil {
		return err
	}

	var respLine []byte
	if respLineWithCRLF[len(respLineWithCRLF)-2] == '\r' {
		respLine = respLineWithCRLF[:len(respLineWithCRLF)-2] // CRLF included
	} else {
		respLine = respLineWithCRLF[:len(respLineWithCRLF)-1] // only LF included
	}

	// http version token
	protocolEndIndex := bytes.IndexByte(respLine, ' ')
	if protocolEndIndex <= 0 {
		return errRespLineNOProtocol
	}
	l.protocol = respLine[:protocolEndIndex]

	// 3-digit status code
	statusCodeStartIndex := protocolEndIndex + 1
	statusCodeEndIndex := statusCodeStartIndex + bytes.IndexByte(respLine[statusCodeStartIndex:], ' ')
	if statusCodeEndIndex <= statusCodeStartIndex {
		return errRespLineNOStatusCode
	}
	statusCode := respLine[statusCodeStartIndex:statusCodeEndIndex]
	if code, err := strconv.Atoi(string(statusCode)); code > 0 && err == nil {
		l.statusCode = code
		l.fullLine = respLineWithCRLF
	} else {
		return util.ErrWrapper(err, "fail to parse status status code %s", statusCode)
	}
	l.statusMsg = respLine[statusCodeEndIndex+1:]
	return nil
}

// RequestLine start line of a http request
type RequestLine struct {
	fullLine []byte
	method   []byte
	uri      uri.URI
	protocol []byte
}

// ParseRequestLine parse request line in stand-alone mode
func ParseRequestLine(reader *bufio.Reader) (*RequestLine, error) {
	reqLine := &RequestLine{}

	if err := reqLine.Parse(reader); err != nil {
		return nil, err
	}
	return reqLine, nil
}

// Parse parse request line
//
// A request-line begins with a method token, followed by a single space
// (SP), the request-target, another single space (SP), the protocol
// version, and ends with CRLF.
func (l *RequestLine) Parse(reader *bufio.Reader) error {
	reqLineWithCRLF, err := parseStartLine(reader)
	if err != nil {
		return err
	}

	var reqLine []byte
	if reqLineWithCRLF[len(reqLineWithCRLF)-2] == '\r' {
		reqLine = reqLineWithCRLF[:len(reqLineWithCRLF)-2] // CRLF included
	} else {
		reqLine = reqLineWithCRLF[:len(reqLineWithCRLF)-1] // only LF included
	}

	// method token
	methodEndIndex := bytes.IndexByte(reqLine, ' ')
	if methodEndIndex <= 0 {
		return errors.New("no method provided")
	}
	method := reqLine[:methodEndIndex]
	changeToUpperCase(method)

	// request target
	reqURIStartIndex := methodEndIndex + 1
	reqURIEndIndex := reqURIStartIndex + bytes.IndexByte(reqLine[reqURIStartIndex:], ' ')
	if reqURIEndIndex <= reqURIStartIndex {
		return errors.New("no request uri provided")
	}
	reqURI := reqLine[reqURIStartIndex:reqURIEndIndex]
	isConnect := IsMethodConnect(method)
	l.uri.Parse(isConnect, reqURI)

	// protocol
	protocolStartIndex := reqURIEndIndex + 1
	protocol := reqLine[protocolStartIndex:]

	l.fullLine = reqLineWithCRLF
	l.method = method
	l.protocol = protocol

	return nil
}

// GetRequestLine get full request line
func (l *RequestLine) GetRequestLine() []byte {
	return l.fullLine
}

// Reset reset request line to nil
func (l *RequestLine) Reset() {
	l.fullLine = l.fullLine[:0]
	l.method = l.method[:0]
	l.uri.Reset()
	l.protocol = l.protocol[:0]
}

// Method request method
func (l *RequestLine) Method() []byte {
	return l.method
}

// PathWithQueryFragment request relative path
func (l *RequestLine) PathWithQueryFragment() []byte {
	return l.uri.PathWithQueryFragment()
}

// Protocol HTTP/1.0, HTTP/1.1 etc.
func (l *RequestLine) Protocol() []byte {
	return l.protocol
}

// HostInfo the host info from request line
func (l *RequestLine) HostInfo() *uri.HostInfo {
	return l.uri.HostInfo()
}

// ChangeHost change host info in request line
func (l *RequestLine) ChangeHost(hostWithPort string) {
	l.uri.ChangeHost(hostWithPort)
}

// ChangePathWithFragment change path info in request line
func (l *RequestLine) ChangePathWithFragment(newPathWithFragment []byte) {
	l.uri.ChangePathWithFragment(newPathWithFragment)
}

func parseStartLine(reader *bufio.Reader) ([]byte, error) {
	startLineWithCRLF, err := reader.ReadBytes('\n')
	if err != nil {
		if err == io.EOF {
			return nil, err
		}
		return nil, util.ErrWrapper(err, "fail to read start line")
	}
	if len(startLineWithCRLF) <= 2 {
		return nil, errors.New("not a http start line")
	}
	return startLineWithCRLF, nil
}
