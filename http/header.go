package http

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/haxii/fastproxy/util"
)

// Header header part of http request & response
type Header struct {
	isConnectionClose      bool
	isProxyConnectionClose bool
	contentLength          int64
	contentType            string
}

// Reset reset header info into default val
func (header *Header) Reset() {
	header.isConnectionClose = false
	header.contentLength = 0
	header.contentType = ""
}

// IsConnectionClose is connection header set to `close`
func (header *Header) IsConnectionClose() bool {
	return header.isConnectionClose
}

// IsProxyConnectionClose is Proxy-Connection header set to `close`
func (header *Header) IsProxyConnectionClose() bool {
	return header.isProxyConnectionClose
}

// ContentType content type in header
func (header *Header) ContentType() string {
	return header.contentType
}

// ContentLength content length header value,
func (header *Header) ContentLength() int64 {
	if header.contentLength > 0 {
		return header.contentLength
	}
	return 0
}

// BodyType return body type parsed from header
func (header *Header) BodyType() BodyType {
	// negative means transfer encoding: -1 means chunked;  -2 means identity
	switch header.contentLength {
	case -1:
		return BodyTypeChunked
	case -2:
		return BodyTypeIdentity
	}
	return BodyTypeFixedSize
}

/*
// IsBodyChunked if body is set `chunked`
func (header *Header) IsBodyChunked() bool {
	// negative means transfer encoding: -1 means chunked;  -2 means identity
	return header.contentLength == -1
}

// IsBodyIdentity if body is set `identity`
func (header *Header) IsBodyIdentity() bool {
	// negative means transfer encoding: -1 means chunked;  -2 means identity
	return header.contentLength == -2
}
*/

// ParseHeaderFields parse http header fields from reader and return the
// header size in reader's buffer, error returned when the header is malformed
//
// Each header field consists of a case-insensitive field name followed
// by a colon (":"), optional leading whitespace, the field value, and
// optional trailing whitespace.
func (header *Header) ParseHeaderFields(reader *bufio.Reader) (int, error) {
	n := 1
	readNum := 0

	for {
		rn, err := header.tryRead(reader, n)
		readNum += rn
		if err == nil {
			return readNum, nil
		}
		if err != errNeedMore {
			return readNum, err
		}
		n = reader.Buffered() + 1
	}
}

var errNeedMore = errors.New("need more data: cannot find trailing LF")

func (header *Header) tryRead(reader *bufio.Reader, n int) (int, error) {
	// do NOT use reader.ReadBytes here
	// which would allocate extra byte memory
	if b, err := reader.Peek(n); err != nil {
		return 0, err
	} else if len(b) == 0 {
		return 0, io.EOF
	}
	// must read buffed bytes
	b := util.PeekBuffered(reader)
	// try to read it into buffer
	headersLen, errParse := header.Parse(b)
	if errParse != nil {
		if errParse == errNeedMore {
			return headersLen, errNeedMore
		}
		return headersLen, errParse
	}
	return headersLen, nil
}

// Parse parse the header fields using given raw header bytes
func (header *Header) Parse(buf []byte) (headerLength int, err error) {
	header.contentLength = 0
	parseBuffer := func(rawHeaderLine []byte) error {
		// Connection, Authenticate and Authorization are single hop Header:
		// http:// www.w3.org/Protocols/rfc2616/rfc2616.txt
		// 14.10 Connection
		// The Connection general-header field allows the sender to specify
		// options that are desired for that particular connection and MUST NOT
		// be communicated by proxies over further connections.
		if isConnectionHeader(rawHeaderLine) {
			changeToLowerCase(rawHeaderLine)
			if bytes.Contains(rawHeaderLine, []byte("close")) {
				header.isConnectionClose = true
			}
			return nil
		}

		if isProxyConnectionHeader(rawHeaderLine) {
			changeToLowerCase(rawHeaderLine)
			if bytes.Contains(rawHeaderLine, []byte("close")) {
				header.isProxyConnectionClose = true
			}
			return nil
		}

		// parse content length
		// content length > 0 means the length of the body
		// content length < 0 means the transfer encoding is set,
		// -1 means chunked
		// -2 means identity
		if isContentLengthHeader(rawHeaderLine) && header.contentLength >= 0 {
			// content-length header can only be set with transfer encoding unset
			lengthBytesIndex := bytes.IndexByte(rawHeaderLine, ':')
			if lengthBytesIndex > 0 {
				lengthBytes := rawHeaderLine[lengthBytesIndex+1:]
				length, _ := strconv.ParseInt(strings.TrimSpace(string(lengthBytes)), 10, 64)
				if length > 0 {
					header.contentLength = length
				}
			}
		} else if isTransferEncodingHeader(rawHeaderLine) {
			if bytes.Contains(rawHeaderLine, []byte("chunked")) {
				header.contentLength = -1
			} else if bytes.Contains(rawHeaderLine, []byte("identity")) {
				header.contentLength = -2
			}
		} else if isContentTypeHeader(rawHeaderLine) {
			contentTypeBytesIndex := bytes.IndexByte(rawHeaderLine, ':')
			if contentTypeBytesIndex >= 0 {
				header.contentType = strings.TrimSpace(
					string(rawHeaderLine[contentTypeBytesIndex+1:]),
				)
			}
		}
		return nil
	}

	// read 1st line
	n := bytes.IndexByte(buf, '\n')
	if n < 0 {
		return 0, errNeedMore
	}
	if (n == 1 && buf[0] == '\r') || n == 0 {
		// empty headers, write \n or \r\n
		return n + 1, nil
	}
	n++
	if e := parseBuffer(buf[:n]); e != nil {
		return 0, e
	}

	// read rest lines
	b := buf
	m := n
	for {
		b = b[m:]
		m = bytes.IndexByte(b, '\n')
		if m < 0 {
			return 0, errNeedMore
		}
		m++
		if e := parseBuffer(b[:m]); e != nil {
			return 0, e
		}
		n += m
		if (m == 2 && b[0] == '\r') || m == 1 {
			return n, nil
		}
	}
}

var connectionHeader = []byte("Connection")
var proxyConnectionHeader = []byte("Proxy-Connection")

func isConnectionHeader(header []byte) bool {
	return hasPrefixIgnoreCase(header, connectionHeader)
}

func isProxyConnectionHeader(header []byte) bool {
	return hasPrefixIgnoreCase(header, proxyConnectionHeader)
}

var contentLengthHeader = []byte("Content-Length")

func isContentLengthHeader(header []byte) bool {
	return hasPrefixIgnoreCase(header, contentLengthHeader)
}

var contentTypeHeader = []byte("Content-Type")

func isContentTypeHeader(header []byte) bool {
	return hasPrefixIgnoreCase(header, contentTypeHeader)
}

var transferEncoding = []byte("Transfer-Encoding")

func isTransferEncodingHeader(header []byte) bool {
	return hasPrefixIgnoreCase(header, transferEncoding)
}

var proxyHeaders = [][]byte{
	// If no Accept-Encoding header exists, Transport will add the headers it can accept
	// and would wrap the response body with the relevant reader.
	// []byte("Accept-Encoding"),
	// curl can add that
	[]byte("Proxy-Connection"),
	[]byte("Proxy-Authenticate"),
	[]byte("Proxy-Authorization"),
}

// IsProxyHeader is the given header a proxy related header
func IsProxyHeader(header []byte) bool {
	for _, proxyHeaderKey := range proxyHeaders {
		if hasPrefixIgnoreCase(header, proxyHeaderKey) {
			return true
		}
	}
	return false
}
