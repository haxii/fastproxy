package http

import (
	"bufio"
	"fmt"
	"io"
	"math"

	"github.com/haxii/fastproxy/bytebufferpool"
	"github.com/haxii/fastproxy/util"
)

//Body http body
type Body struct{}

//BodyType how http body is formed
type BodyType int

const (
	//BodyTypeFixedSize body size is specified in `content-length` header
	BodyTypeFixedSize BodyType = iota
	//BodyTypeChunked body is chunked with `Transfer-Encoding: chunked` in header
	BodyTypeChunked
	//BodyTypeIdentity body is identity with `Transfer-Encoding: identity` in header
	BodyTypeIdentity
)

//BodyWrapper body reader helper
type BodyWrapper func(isChunkHeader bool, data []byte) error

//Parse parse body from reader and wraps data in BodyWrapper
func (b *Body) Parse(reader *bufio.Reader, bodyType BodyType,
	contentLength int64, w BodyWrapper) error {
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
	return nil
}

func parseBodyFixedSize(src *bufio.Reader, w BodyWrapper, contentLength int64) error {
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

		if err := w(false, b[:bytesShouldRead]); err != nil {
			return err
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

func parseBodyChunked(src *bufio.Reader, w BodyWrapper) error {
	buffer := bytebufferpool.Get()
	defer bytebufferpool.Put(buffer)

	for {
		//read and calculate chunk size
		buffer.Reset()
		chunkSize, err := parseChunkSize(src, buffer)
		if err != nil {
			return err
		}
		if err := w(true, buffer.B); err != nil {
			return err
		}
		//copy the chunk
		if err := parseBodyFixedSize(src, w,
			//2 means the length of `\r\n` i.e. CRLF
			int64(chunkSize+2)); err != nil {
			return err
		}
		if chunkSize == 0 {
			return nil
		}
	}
}

func parseBodyIdentity(src *bufio.Reader, w BodyWrapper) error {
	if err := parseBodyFixedSize(src, w, math.MaxInt64); err != nil {
		//TODO: make sure the io.EOF is reachable
		if err == io.EOF {
			return nil
		}
		return err
	}
	return nil
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
