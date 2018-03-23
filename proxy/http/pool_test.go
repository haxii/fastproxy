package http

import (
	"bufio"
	"io"
	"strings"
	"testing"

	"github.com/fastfork/fastproxy/bytebufferpool"
	"github.com/haxii/fastproxy/http"
)

func TestRequestPool(t *testing.T) {
	for i := 0; i < 10; i++ {
		reqPool := &RequestPool{}
		request := reqPool.Acquire()
		if request.GetWriteSize() != 0 {
			t.Fatal("request pool can't acquire an empty request")
		}
		request.AddWriteSize(10)
		if request.GetWriteSize() != 10 {
			t.Fatal("request pool can't acquire an normal request")
		}
		reqPool.Release(request)
	}
}

func TestResponsePool(t *testing.T) {
	s := "HTTP/1.1 200 ok\r\n\r\n"
	for i := 0; i < 10; i++ {
		respPool := &ResponsePool{}
		resp := respPool.Acquire()
		if resp.GetSize() != 0 {
			t.Fatal("request pool can't acquire an empty response")
		}
		br := bufio.NewReader(strings.NewReader(s))
		byteBuffer := bytebufferpool.MakeFixedSizeByteBuffer(100)
		bw := bufio.NewWriter(byteBuffer)
		sHijacker := &simpleHijacker{}
		resp.SetHijacker(sHijacker)
		err := resp.WriteTo(bw)
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		err = resp.ReadFrom(false, br)
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		if resp.GetSize() != 19 {
			t.Fatal("request pool can't acquire an normal response")
		}
		respPool.Release(resp)
	}
}

type simpleHijacker struct{}

func (s *simpleHijacker) OnRequest(header http.Header, rawHeader []byte) io.Writer {
	return nil
}

func (s *simpleHijacker) HijackResponse() io.Reader {
	return nil
}

func (s *simpleHijacker) OnResponse(respLine http.ResponseLine,
	header http.Header, rawHeader []byte) io.Writer {
	return nil
}
