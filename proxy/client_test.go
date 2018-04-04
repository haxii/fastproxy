package proxy

import (
	"testing"

	"github.com/haxii/fastproxy/bytebufferpool"
)

func TestParallelWriteHeader(t *testing.T) {
	//TODO: @xiangyu more tests coverage
	buffer1 := bytebufferpool.Get()
	defer bytebufferpool.Put(buffer1)

	var additionalDst string
	n, _ := parallelWriteHeader(buffer1, func(p []byte) { additionalDst = string(p) }, []byte("Host: www.google.com\r\nUser-Agent: curl/7.54.0\r\n\r\n"))
	t.Error("\n", buffer1.B, "\n", additionalDst, "\n", n, "==", len(buffer1.B), "?=", len(additionalDst))
	buffer1.Reset()

	n, _ = parallelWriteHeader(buffer1, func(p []byte) { additionalDst = string(p) }, []byte("Host: www.google.com\r\nUser-Agent: curl/7.54.0\n\n"))
	t.Error("\n", buffer1.B, "\n", additionalDst, "\n", n, "==", len(buffer1.B), "?=", len(additionalDst))
	buffer1.Reset()

	n, _ = parallelWriteHeader(buffer1, func(p []byte) { additionalDst = string(p) }, []byte("Host: www.google.com\r\nProxy-Connection: Keep-Alive\r\nUser-Agent: curl/7.54.0\r\n\r\n"))
	t.Error("\n", buffer1.B, "\n", additionalDst, "\n", n, "==", len(buffer1.B), "?=", len(additionalDst))
}
