package util

import (
	"io"
	"testing"

	"github.com/balinor2017/fastproxy/bytebufferpool"
)

func TestWriteWithValidation(t *testing.T) {
	testWriteWithValidation(t, nil, "12", nil, 0)
	bytebuffer := bytebufferpool.MakeFixedSizeByteBuffer(5)
	bytebuffer.Reset()
	testWriteWithValidation(t, bytebuffer, "123456789", io.ErrShortBuffer, 5)
	bytebuffer.Reset()
	testWriteWithValidation(t, bytebuffer, "1234", nil, 4)
}

func testWriteWithValidation(t *testing.T, w io.Writer, testString string, expErr error, expWriteLength int) {
	n, err := WriteWithValidation(w, []byte(testString))
	if err != expErr {
		t.Fatalf("expected error : %s, but get unexpected error: %s", expErr, err)
	}
	if n != expWriteLength {
		t.Fatalf("expected write length is %d, but it is %d ", expWriteLength, n)
	}
}
