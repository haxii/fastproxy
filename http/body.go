package http

import (
	"bufio"
	"fmt"
	"github.com/haxii/fastproxy/bytebufferpool"
	"github.com/haxii/fastproxy/util"
	"io"
	"math"
)

// Body http body
type Body struct{}

// BodyType how http body is formed
type BodyType int

const (
	// BodyTypeFixedSize body size is specified in `content-length` header
	BodyTypeFixedSize BodyType = iota
	// BodyTypeChunked body is chunked with `Transfer-Encoding: chunked` in header
	BodyTypeChunked
	// BodyTypeIdentity body is identity with `Transfer-Encoding: identity` in header
	BodyTypeIdentity
)

// BodyWrapper body reader helper
type BodyWrapper func(isChunkHeader bool, data []byte) (int, error)

// Parse parse body from reader and wraps data in BodyWrapper
func (b *Body) Parse(reader *bufio.Reader, bodyType BodyType,
	contentLength int64, w BodyWrapper) (int, error) {
	switch bodyType {
	case BodyTypeFixedSize:
		if contentLength > 0 {
			return parseBodyFixedSize(reader, w, contentLength)
		}
	case BodyTypeChunked:
		return parseBodyChunked(reader, w)
	case BodyTypeIdentity:
		return parseBodyIdentity(reader, w)
	}
	return 0, nil
}

func parseBodyFixedSize(src *bufio.Reader, w BodyWrapper, contentLength int64) (int, error) {
	byteStillNeeded := contentLength
	var wn int
	for {
		// read one more bytes
		if b, _ := src.Peek(1); len(b) == 0 {
			return wn, io.EOF
		}

		// must read buffed bytes
		b := util.PeekBuffered(src)

		// write read bytes into dst
		_bytesShouldRead := int64(len(b))
		if byteStillNeeded <= _bytesShouldRead {
			_bytesShouldRead = byteStillNeeded
		}
		byteStillNeeded -= _bytesShouldRead
		bytesShouldRead := int(_bytesShouldRead)

		n, err := w(false, b[:bytesShouldRead])
		if err != nil {
			return wn, err
		}
		wn += n

		// discard wrote bytes
		if _, err := src.Discard(bytesShouldRead); err != nil {
			return wn, util.ErrWrapper(err, "fail to write request body")
		}

		// test if still read more bytes
		if byteStillNeeded == 0 {
			return wn, nil
		}
	}
}

func parseBodyChunked(src *bufio.Reader, w BodyWrapper) (int, error) {
	buffer := bytebufferpool.Get()
	defer bytebufferpool.Put(buffer)
	var wn, n int
	for {
		// read and calculate chunk size
		buffer.Reset()
		chunkSize, err := parseChunkSize(src, buffer)
		if err != nil {
			return wn, err
		}
		if n, err = w(true, buffer.B); err != nil {
			return wn, err
		}
		wn += n
		// copy the chunk
		if n, err = parseBodyFixedSize(src, w,
			// 2 means the length of `\r\n` i.e. CRLF
			int64(chunkSize+2)); err != nil {
			return wn, err
		}
		wn += n
		if chunkSize == 0 {
			return wn, nil
		}
	}
}

func parseBodyIdentity(src *bufio.Reader, w BodyWrapper) (int, error) {
	var n int
	var err error
	if n, err = parseBodyFixedSize(src, w, math.MaxInt64); err != nil {
		// TODO: make sure the io.EOF is reachable
		if err == io.EOF {
			return n, nil
		}
		return n, err
	}
	return n, nil
}

func parseChunkSize(r *bufio.Reader, buffer *bytebufferpool.ByteBuffer) (int, error) {
	n, err := util.ReadHexInt(r, buffer)
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
