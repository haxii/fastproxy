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

	testFixedSizeByteBuffer(t, correctData, dataBuffer, 4, nil)

	dataBuffer.Reset()
	testFixedSizeByteBuffer(t, wrongData, dataBuffer, 5, io.ErrShortBuffer)

	dataBuffer.Reset()
	testFixedSizeByteBuffer(t, []byte(""), dataBuffer, 0, nil)

	dataBuffer.Reset()
	testFixedSizeByteBuffer(t, correctData, dataBuffer, 4, nil)
	testFixedSizeByteBuffer(t, correctData, dataBuffer, 5, io.ErrShortBuffer)
}

func testFixedSizeByteBuffer(t *testing.T, data []byte, dataBuffer *FixedSizeByteBuffer, expSize int, expErr error) {
	writingSize, err := dataBuffer.Write(data)
	if err != nil {
		if err != expErr {
			t.Fatalf("Expected error:%s, but get unexpected error: %s", expErr.Error(), err.Error())
		}
	} else {
		if writingSize != expSize {
			t.Fatal("write wrong number of data in dataBuffer")
		}
		dataBufferResult := dataBuffer.Bytes()

		if !bytes.Equal(dataBufferResult, data) {
			t.Fatal("write wrong data in dataBuffer")
		}
		if dataBuffer.Len() != expSize {
			t.Fatal("write data error")
		}
	}
}
