package proxy

import (
	"io"
	"net"

	"github.com/haxii/fastproxy/header"
)

//Sniffer http sniffer
type Sniffer interface {
	// GetRequestWriter return a request writer based on uri & header
	GetRequestWriter(
		host string, method, path []byte,
		header header.Header, rawHeader []byte) io.Writer
	// GetResponseWriter return a response writer based on status code & header
	GetResponseWriter(statusCode int,
		header header.Header, rawHeader []byte) io.Writer
}

//SnifferPool pooling sniffer instances
type SnifferPool interface {
	// Get get a sniffer with client address
	Get(net.Addr) Sniffer
	// Put put a sniffer back to pool
	Put(Sniffer)
}
