package proxy

import (
	"io"
	"net"

	"github.com/haxii/fastproxy/http"
)

// Hijacker hijacker of each http connection and decrypted https connection
type Hijacker interface {
	// OnRequest is a sniffer handler.
	// Which gives the request header in parameters then
	// write request body in the writer returned
	OnRequest(header http.Header, rawHeader []byte) io.Writer

	// OnResponse is a sniffer handler
	// Which gives the response header in parameters then
	// write response body in the writer returned
	OnResponse(statusLine http.ResponseLine, header http.Header, rawHeader []byte) io.Writer

	// HijackResponse is a hijack handler.
	// A non-nil reader means should stop the request to the target
	// server then return the reader's response
	HijackResponse() io.Reader
}

// HijackerPool pooling hijacker instances
type HijackerPool interface {
	// Get get a hijacker with client address
	Get(clientAddr net.Addr, host string, method, path []byte, userdata *UserData) Hijacker
	// Put put a hijacker back to pool
	Put(Hijacker)
}

var defaultNilHijacker = &nilHijacker{}

type nilHijacker struct{}

func (*nilHijacker) OnRequest(header http.Header, rawHeader []byte) io.Writer {
	return nil
}

func (*nilHijacker) OnResponse(respLine http.ResponseLine, header http.Header, rawHeader []byte) io.Writer {
	return nil
}

func (*nilHijacker) HijackResponse() io.Reader {
	return nil
}
