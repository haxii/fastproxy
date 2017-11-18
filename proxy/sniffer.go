package proxy

import (
	"io"
	"net"

	"github.com/haxii/fastproxy/header"
)

//Sniffer http sniffer
type Sniffer interface {
	// GetRequestWriter return a request writer based on uri & header
	GetRequestWriter(uri []byte, header header.Header) io.Writer
	// GetResponseWriter return a response writer based on status code & header
	GetResponseWriter(statusCode int, header header.Header) io.Writer
}

//SnifferPool pooling sniffer instances
type SnifferPool interface {
	// Get get a sniffer with client address
	Get(net.Addr) Sniffer
	// Put put a sniffer back to pool
	Put(Sniffer)
}
