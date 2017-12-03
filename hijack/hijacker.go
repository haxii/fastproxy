package hijack

import (
	"io"
	"net"

	"github.com/haxii/fastproxy/http"
)

//Hijacker hijacker of each http connection
// Sniffer: `OnRequest` & `OnResponse`
// Modifer: `HijackResponse`
type Hijacker interface {
	// OnRequest give the request header in parameters then
	// write request body in the writer returned
	OnRequest(header http.Header, rawHeader []byte) io.Writer

	// OnResponse give the response header in parameters then
	// write response body in the writer returned
	OnResponse(statusCode int, header http.Header, rawHeader []byte) io.Writer

	// HijackResponse return a response hijacking reader
	//  a non-nil reader means proxy would stop the request to target
	//  server then return the reader's response
	HijackResponse() io.Reader
}

//HijackerPool pooling hijacker instances
type HijackerPool interface {
	// Get get a hijacker with client address
	Get(clientAddr net.Addr, host string, method, path []byte) Hijacker
	// Put put a hijacker back to pool
	Put(Hijacker)
}
