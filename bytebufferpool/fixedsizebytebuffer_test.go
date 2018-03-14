package bytebufferpool

import (
	"bytes"
	"io"
	"testing"
)

func Test_fixedSizeByteBuffer(t *testing.T) {
	var wrongData []byte
	wrongData = []byte("1234567")
	var dataBuffer = MakeFixedSizeByteBuffer(5)
	correctData := []byte("1234")

	writingSize, err := dataBuffer.Write(correctData)
	if writingSize != 4 {
		t.Fatal("write wrong number of data in dataBuffer")
	}
	dataBufferResult := dataBuffer.Bytes()

	if !bytes.Equal(dataBufferResult, correctData) {
		t.Fatal("write wrong data in dataBuffer")
	}
	if dataBuffer.Len() != 4 {
		t.Fatal("write data error")
	}
	writingSize, err = dataBuffer.Write(wrongData)
	if err != io.ErrShortBuffer {
		t.Fatal("Write data error: data should not write in dataBuffer")
	}
	if dataBuffer.Len() != 5 {
		t.Fatal("Write data error: some data didn't write in dataBuffer")
	}

	dataBuffer.Reset()
	if dataBuffer.Len() != 0 {
		t.Fatal("Reset data error: data buffer do not reset")
	}
	if !bytes.Equal(dataBuffer.Bytes(), []byte("")) {
		t.Fatal("Reset data error: data buffer bytes do not reset")
	}

	dataBuffer.Reset()
	writingSize, err = dataBuffer.Write(wrongData)
	if err != io.ErrShortBuffer || writingSize != 5 {
		t.Fatal("Write data error: write too much data in dataBuffer")
	}

	if !bytes.Equal(dataBuffer.Bytes(), []byte("12345")) {
		t.Fatal("Write data error: write data error")
	}

	dataBuffer.Reset()

	writingSize, err = dataBuffer.Write(correctData)
	writingSize, err = dataBuffer.Write(correctData)
	if err != io.ErrShortBuffer || writingSize != 1 {
		t.Fatal("Write data error: write too much data in dataBuffer")
	}
	if !bytes.Equal(dataBuffer.Bytes(), []byte("12341")) {
		t.Fatal("Write data error: write unexpect data in dataBuffer")
	}
	if dataBuffer.Len() != 5 {
		t.Fatal("Write data error: some data didn't write in dataBuffer")
	}

}
