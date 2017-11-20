package util

import (
	"bufio"
	"fmt"
	"io"
)

//WriteWithValidation write p into w and validate the written data length
func WriteWithValidation(w io.Writer, p []byte) error {
	wn, err := w.Write(p)
	if err != nil {
		return err
	}
	if wn != len(p) {
		return io.ErrShortWrite
	}
	return nil
}

//ErrWrapper wrap the error message except io.EOF
func ErrWrapper(err error, msg string, args ...interface{}) error {
	//do not wrap io.EOF
	if err == io.EOF {
		return err
	}
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
