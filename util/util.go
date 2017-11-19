package util

import (
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
