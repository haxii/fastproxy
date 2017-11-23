package hijack

import (
	"io"
	"net"

	"github.com/haxii/fastproxy/http"
)

//Hijacker http hijacker
type Hijacker interface {
	// GetRequestWriter return a request sniffing writer based on uri & header
	GetRequestWriter(
		host string, method, path []byte,
		header http.Header, rawHeader []byte) io.Writer
	// GetResponseReader return a response hijacking reader
	//  a non-nil reader means proxy would stop the request to target
	//  server then return the reader's response
	GetResponseReader() io.Reader
	// GetResponseWriter return a response sniffing writer based on status code & header
	GetResponseWriter(statusCode int,
		header http.Header, rawHeader []byte) io.Writer
}

//HijackerPool pooling hijacker instances
type HijackerPool interface {
	// Get get a hijacker with client address
	Get(net.Addr) Hijacker
	// Put put a hijacker back to pool
	Put(Hijacker)
}
