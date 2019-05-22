package proxy

import (
	"io"
	"net"

	"github.com/haxii/fastproxy/http"
	"github.com/haxii/fastproxy/superproxy"
)

// Hijacker hijacker of each http connection and decrypted https connection
type Hijacker interface {
	// HijackRequest is a request hijack handler.
	// which provides the ability to change the request header and assigned super proxy without breaking the request.
	// Return new super header to change the original header, please do NOT change payload related fields
	// (like Content-Length, Transfer-Encoding etc.) to avoid exceptions.
	// For advanced Hijack options, use the HijackResponse instead
	HijackRequest(header http.Header, rawHeader []byte, superProxy **superproxy.SuperProxy) []byte

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

func (*nilHijacker) HijackRequest(header http.Header, rawHeader []byte, superProxy **superproxy.SuperProxy) []byte {
	return nil
}

func (*nilHijacker) OnRequest(header http.Header, rawHeader []byte) io.Writer {
	return nil
}

func (*nilHijacker) OnResponse(respLine http.ResponseLine, header http.Header, rawHeader []byte) io.Writer {
	return nil
}

func (*nilHijacker) HijackResponse() io.Reader {
	return nil
}
