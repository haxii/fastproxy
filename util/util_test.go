package util

import (
	"io"
	"testing"

	"github.com/haxii/fastproxy/bytebufferpool"
)

func TestWriteWithValidation(t *testing.T) {
	var err error
	n, err := WriteWithValidation(nil, []byte("12"))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if n != 0 {
		t.Fatal("Nil writer shouldn't write into anything")
	}
	bytebuffer := bytebufferpool.MakeFixedSizeByteBuffer(5)
	_, err = WriteWithValidation(bytebuffer, []byte("12345678"))
	if err == nil {
		t.Fatal("expected error: short buffer")
	}
	if err != io.ErrShortBuffer {
		t.Fatalf("expected error: short buffer, but get unexpected error: %s", err)
	}
	bytebuffer = bytebufferpool.MakeFixedSizeByteBuffer(10)
	_, err = WriteWithValidation(bytebuffer, []byte("123456"))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
}
