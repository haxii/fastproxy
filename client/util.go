package client

import (
	"bufio"
	"bytes"
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
	startLineScheme = []byte("http://")
	startLineSP     = byte(' ')
	startLineCRLF   = []byte("\r\n")
)

const defaultHTTPPort = "80"

func writeRequestLine(bw *bufio.Writer, fullURL bool,
	method []byte, hostWithPort string, path, protocol []byte) error {
	host, port, err := net.SplitHostPort(hostWithPort)
	if err != nil {
		return err
	}
	write := func(b []byte) error {
		if nw, err := bw.Write(b); err != nil {
			return err
		} else if nw != len(b) {
			return io.ErrShortWrite
		}
		return nil
	}
	writeStr := func(s string) error {
		if nw, err := bw.WriteString(s); err != nil {
			return err
		} else if nw != len(s) {
			return io.ErrShortWrite
		}
		return nil
	}
	if err := write(method); err != nil {
		return err
	}
	if err := bw.WriteByte(startLineSP); err != nil {
		return err
	}
	if fullURL {
		if err := write(startLineScheme); err != nil {
			return err
		}
		if port != defaultHTTPPort {
			if err := writeStr(hostWithPort); err != nil {
				return err
			}
		} else {
			if err := writeStr(host); err != nil {
				return err
			}
		}
	}
	if err := write(path); err != nil {
		return err
	}
	if err := bw.WriteByte(startLineSP); err != nil {
		return err
	}
	if err := write(protocol); err != nil {
		return err
	}
	return write(startLineCRLF)
}
