package client

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
)

var (
	methodGet    = []byte("GET")
	methodHead   = []byte("HEAD")
	methodPut    = []byte("PUT")
	methodDelete = []byte("DELETE")
)

func isHead(method []byte) bool {
	return bytes.Equal(method, methodHead)
}

func isGet(method []byte) bool {
	return bytes.Equal(method, methodGet)
}

//isHeadOrGet get, head as idempotent methods
func isHeadOrGet(method []byte) bool {
	return isHead(method) || isGet(method)
}

var (
	startLineScheme  = []byte("http://")
	startLineSP      = byte(' ')
	startLinePathSep = byte('/')
	startLineCRLF    = []byte("\r\n")
)

const defaultHTTPPort = "80"

var errNilBufioWriter = errors.New("nil bufio writer")

func writeRequestLine(bw *bufio.Writer, fullURL bool,
	method []byte, hostWithPort string, path, protocol []byte) (int, error) {

	writeSize := 0
	write := func(b []byte) error {
		var nw int
		var err error
		if bw == nil {
			return errNilBufioWriter
		}
		if nw, err = bw.Write(b); err != nil {
			return err
		} else if nw != len(b) {
			return io.ErrShortWrite
		}
		writeSize += nw
		return nil
	}
	writeStr := func(s string) error {
		var nw int
		var err error
		if nw, err = bw.WriteString(s); err != nil {
			return err
		} else if nw != len(s) {
			return io.ErrShortWrite
		}
		writeSize += nw
		return nil
	}
	if err := write(method); err != nil {
		return writeSize, err
	}
	if err := bw.WriteByte(startLineSP); err != nil {
		return writeSize, err
	}
	writeSize++
	if fullURL {
		host, port, err := net.SplitHostPort(hostWithPort)
		if err != nil {
			return 0, err
		}

		if err := write(startLineScheme); err != nil {
			return writeSize, err
		}
		if port != defaultHTTPPort {
			if err := writeStr(hostWithPort); err != nil {
				return writeSize, err
			}
		} else {
			if err := writeStr(host); err != nil {
				return writeSize, err
			}
		}
	}
	if len(path) == 0 {
		if err := bw.WriteByte(startLinePathSep); err != nil {
			return writeSize, err
		}
	} else {
		if path[0] != startLinePathSep {
			if err := bw.WriteByte(startLinePathSep); err != nil {
				return writeSize, err
			}
		}
		if err := write(path); err != nil {
			return writeSize, err
		}
	}
	if err := bw.WriteByte(startLineSP); err != nil {
		return writeSize, err
	}
	writeSize++
	if err := write(protocol); err != nil {
		return writeSize, err
	}

	if err := write(startLineCRLF); err != nil {
		return writeSize, err
	}

	return writeSize, nil
}
