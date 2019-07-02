package proxy

import (
	"crypto/tls"
	"io"
	"net"

	"github.com/haxii/fastproxy/http"
	"github.com/haxii/fastproxy/superproxy"
)

// Hijacker hijacker of each http connection and decrypted https connection
// For HTTP Connections, the call chain is:
// - RewriteHost -> BeforeRequest -> Resolve -> SuperProxy -> HijackResponse -> Dial/DialTLS -> OnRequest -> OnResponse
// For HTTPS Tunnels, the call chain is:
// - RewriteHost -> SSLBump(false) -> Resolve -> SuperProxy -> Dial/DialTLS
// For HTTPS Sniffer, the call chain is:
// - RewriteHost -> SSLBump(true) -> RewriteTLSServerName -> BeforeRequest -> Resolve -> SuperProxy -> HijackResponse -> Dial/DialTLS -> OnRequest -> OnResponse
type Hijacker interface {
	// RewriteHost rewrites the incoming host and port, return a nil newHost or nil newPort to end the request
	RewriteHost() (newHost, newPort string)

	// SSLBump returns if the https connection should be decrypted
	SSLBump() bool

	// RewriteTLSServerName returns the new tls client handshake server name for SSL bump
	RewriteTLSServerName(string) string

	// BeforeRequest is a request hijack handler.
	// which provides the ability to change the request resources and header.
	// Return new super header to change the original header, please do NOT change payload related fields
	// (like Content-Length, Transfer-Encoding etc.) to avoid exceptions.
	// For advanced Hijack options, use the HijackResponse instead
	BeforeRequest(path []byte, header http.Header, rawHeader []byte) (newPath, newRawHeader []byte)

	// Resolve performs a DNS Lookup, should not block for long time
	Resolve() net.IP

	// SuperProxy returns the super-proxy
	SuperProxy() *superproxy.SuperProxy

	// Block blocks the request and returns a error to client
	// For advanced blocking options, use the HijackResponse instead
	Block() bool

	// HijackResponse is a hijack handler.
	// A non-nil reader means should stop the request to the target
	// server then return the reader's response
	HijackResponse() io.Reader

	// Dial called every TCP connection made to addr, default dialer is used when nil func returned
	Dial() func(addr string) (net.Conn, error)

	// DialTLS called every TLS connection made to addr, default dialer is used when nil func returned
	DialTLS() func(addr string, tlsConfig *tls.Config) (net.Conn, error)

	// OnRequest is a sniffer handler.
	// Which gives the request header in parameters then
	// write request body in the writer returned
	OnRequest(path []byte, header http.Header, rawHeader []byte) io.Writer

	// OnResponse is a sniffer handler
	// Which gives the response header in parameters then
	// write response body in the writer returned
	OnResponse(statusLine http.ResponseLine, header http.Header, rawHeader []byte) io.Writer
}

// HijackerPool pooling hijacker instances
type HijackerPool interface {
	// Get get a hijacker with client address
	Get(clientAddr net.Addr, isHTTPS bool, host, port string) Hijacker
	// Put put a hijacker back to pool
	Put(Hijacker)
}
