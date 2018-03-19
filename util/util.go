package util

import (
	"bufio"
	"fmt"
	"io"
)

//WriteWithValidation write p into w and validate the written data length
// pass a nil writer does nothing and produce a nil error
func WriteWithValidation(w io.Writer, p []byte) (int, error) {
	if w == nil {
		return 0, nil
	}
	wn, err := w.Write(p)
	if err != nil {
		return wn, err
	}
	if wn != len(p) {
		return wn, io.ErrShortWrite
	}
	return wn, nil
}

//ErrWrapper wrap the error message except io.EOF
func ErrWrapper(err error, msg string, args ...interface{}) error {
	if err == nil {
		return fmt.Errorf(msg, args...)
	}
	return fmt.Errorf(msg+" [error "+err.Error()+"]", args...)
}

//PeekBuffered peek buffered bytes for buffer reader
func PeekBuffered(r *bufio.Reader) []byte {
	if r.Buffered() == 0 {
		return nil
	}
	buf, err := r.Peek(r.Buffered())
	if len(buf) == 0 || err != nil {
		panic(fmt.Sprintf("bufio.Reader.Peek() returned unexpected data (%q, %v)", buf, err))
	}
	return buf
}
