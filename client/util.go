package client

import (
	"bufio"
	"bytes"
	"io"
	"strconv"
)

var (
	methodGet    = []byte("GET")
	methodHead   = []byte("HEAD")
	methodPut    = []byte("PUT")
	methodDelete = []byte("DELETE")
)

//isIdempotent idempotent methods: get, head, put
func isIdempotent(method []byte) bool {
	return bytes.Equal(method, methodGet) ||
		bytes.Equal(method, methodHead) ||
		bytes.Equal(method, methodDelete) ||
		bytes.Equal(method, methodPut)
}

var (
	startLineScheme = []byte("http://")
	startLineColon  = byte(':')
	startLineSP     = byte(' ')
	startLineCRLF   = []byte("\r\n")
)

const defaultHTTPPort uint16 = 80

func writeRequestLine(bw *bufio.Writer, fullURL bool,
	method, host []byte, port uint16, path, protocol []byte) error {
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
		if err := write(host); err != nil {
			return err
		}
		if port != defaultHTTPPort {
			if err := bw.WriteByte(startLineColon); err != nil {
				return err
			}
			if err := writeStr(strconv.FormatInt(int64(port), 10)); err != nil {
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
	if err := bw.WriteByte(startLineSP); err != nil {
		return err
	}
	if err := write(startLineCRLF); err != nil {
		return err
	}
	return nil
}
