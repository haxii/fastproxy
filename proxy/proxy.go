package proxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/client"
	"github.com/haxii/fastproxy/http"
	"github.com/haxii/fastproxy/mitm"
	"github.com/haxii/fastproxy/server"
	"github.com/haxii/fastproxy/servertime"
	"github.com/haxii/fastproxy/superproxy"
	"github.com/haxii/fastproxy/uri"
	"github.com/haxii/fastproxy/util"
	"github.com/haxii/log"
)

// DefaultServerShutdownWaitTime used when ServerShutdownWaitTime not set
var DefaultServerShutdownWaitTime = time.Second * 30

// Proxy is a HTTP / HTTPS forward proxy with the ability to
// sniff or modify the forwarding traffic
type Proxy struct {
	// ProxyLogger proxy error logger
	Logger log.Logger

	// Per-connection buffer size for requests' reading.
	// This also limits the maximum header size.
	//
	// Increase this buffer if your clients send multi-KB RequestURIs
	// and/or multi-KB headers (for example, BIG cookies).
	//
	// Default buffer size is used if not set.
	ReadBufferSize int

	// Per-connection buffer size for responses' writing.
	//
	// Default buffer size is used if not set.
	WriteBufferSize int

	// BufioPool buffer reader and writer pool
	bufioPool *bufiopool.Pool

	// server basic connection server used by proxy
	server server.Server

	// MaxClientIdleDuration max idle duration for client connection
	// TODO: http? @daizong refer fasthttp's idle handler
	ServerIdleDuration time.Duration

	// Concurrency max simultaneous connections per client
	ServerConcurrency int

	// ServerShutdownWaitTime max waiting time for connected clients when server shuts down
	// DefaultServerShutdownWaitTime is used when not set
	ServerShutdownWaitTime time.Duration

	// client proxy uses a http client to dial a remote host for incoming requests
	client client.Client

	// ForwardConcurrencyPerHost max forward connections limit per target host
	ForwardConcurrencyPerHost int

	// ForwardIdleConnDuration max forward connection's idle duration for target host
	ForwardIdleConnDuration time.Duration

	// ForwardReadTimeout read timeout for target forwarding host
	ForwardReadTimeout time.Duration
	// ForwardWriteTimeout write timeout for target forwarding host
	ForwardWriteTimeout time.Duration
	//TODO: integrate this timeout with forwarding may be?

	// used by server and client: http request and response pool
	reqPool  RequestPool
	respPool ResponsePool

	// Handler proxy handler
	Handler Handler
}

// Handler proxy handlers
type Handler struct {
	// ShouldAllowConnection should allow the connection to proxy, return false to drop the conn
	ShouldAllowConnection func(connAddr net.Addr) bool

	// HTTPSDecryptEnable test if host's https connection should be decrypted
	ShouldDecryptHost func(host string) bool

	// URLProxy url specified proxy, nil path means this is a un-decrypted https traffic
	URLProxy func(hostInfo *uri.HostInfo, path []byte) *superproxy.SuperProxy

	// LookupIP returns ip string, should not block for long time
	LookupIP func(domain string) net.IP

	// hijacker pool for making a hijacker for every incoming request
	HijackerPool HijackerPool

	// MITMCertAuthority root certificate authority used for https decryption
	MITMCertAuthority *tls.Certificate
}

// Serve serve on the provided ip address
func (p *Proxy) Serve(network, addr string) error {
	if p.Logger == nil {
		return errors.New("no logger provided")
	}
	p.bufioPool = bufiopool.New(p.ReadBufferSize, p.WriteBufferSize)

	// setup server
	ln, lnErr := net.Listen(network, addr)
	if lnErr != nil {
		return lnErr
	}
	if p.ServerShutdownWaitTime <= 0 {
		p.ServerShutdownWaitTime = DefaultServerShutdownWaitTime
	}
	p.server.Listener = server.NewGracefulListener(ln, p.ServerShutdownWaitTime)
	p.server.Concurrency = p.ServerConcurrency
	p.server.ServiceName = "ProxyMNG"
	p.server.Logger = p.Logger
	p.server.ConnHandler = p.serveConn
	p.server.OnConcurrencyLimitExceeded = p.serveConnOnLimitExceeded

	// setup client
	p.client.BufioPool = p.bufioPool
	p.client.MaxConnsPerHost = p.ForwardConcurrencyPerHost
	p.client.MaxIdleConnDuration = p.ForwardIdleConnDuration
	p.client.ReadTimeout = p.ForwardReadTimeout
	p.client.WriteTimeout = p.ForwardWriteTimeout

	// setup handler
	if p.Handler.ShouldAllowConnection == nil {
		p.Handler.ShouldAllowConnection = func(net.Addr) bool {
			return true
		}
	}
	if p.Handler.ShouldDecryptHost == nil {
		p.Handler.ShouldDecryptHost = func(string) bool {
			return false
		}
	}
	if p.Handler.URLProxy == nil {
		p.Handler.URLProxy = func(hostInfo *uri.HostInfo, path []byte) *superproxy.SuperProxy {
			return nil
		}
	}
	if p.Handler.LookupIP == nil {
		p.Handler.LookupIP = func(domain string) net.IP {
			return nil
		}
	}

	return p.server.ListenAndServe()
}

// ShutDown shut down the server gracefully
func (p *Proxy) ShutDown() error {
	return p.server.Listener.Close()
}

func (p *Proxy) serveConnOnLimitExceeded(c net.Conn) {
	writeFastError(c, http.StatusServiceUnavailable,
		"The connection cannot be served because proxy's concurrency limit exceeded")
}

func (p *Proxy) serveConn(c net.Conn) error {
	if !p.Handler.ShouldAllowConnection(c.RemoteAddr()) {
		return nil
	}
	// convert c into a http request
	reader := p.bufioPool.AcquireReader(c)
	req := p.reqPool.Acquire()
	releaseReqAndReader := func() {
		p.reqPool.Release(req)
		p.bufioPool.ReleaseReader(reader)
	}
	defer releaseReqAndReader()
	var err error
	var rn int

	for {
		// parse start line of the request: a.k.a. request line
		if p.ServerIdleDuration == 0 {
			rn, err = req.parseStartLine(reader)
		} else {
			idleChan := make(chan struct{})
			go func() {
				rn, err = req.parseStartLine(reader)
				idleChan <- struct{}{}
			}()
			select {
			case <-idleChan:
			case <-time.After(p.ServerIdleDuration):
				// idle out of max idle duration, return to close connection
				return nil
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return util.ErrWrapper(err, "fail to read http request header")
		}

		// discard direct HTTP requests
		if len(req.reqLine.HostInfo().HostWithPort()) == 0 {
			if e := writeFastError(c, http.StatusBadRequest,
				"This is a proxy server. Does not respond to non-proxy requests.\n"); e != nil {
				return util.ErrWrapper(e, "fail to response non-proxy request")
			}
			return nil
		}

		// do a manual DNS look up
		domain := req.reqLine.HostInfo().Domain()
		if len(domain) > 0 {
			ip := p.Handler.LookupIP(domain)
			req.reqLine.HostInfo().SetIP(ip)
		}

		// set requests proxy
		// TODO: session in context refactoring
		superProxy := p.Handler.URLProxy(req.reqLine.HostInfo(), req.PathWithQueryFragment())
		if len(req.reqLine.HostInfo().HostWithPort()) == 0 {
			if e := writeFastError(c, http.StatusSessionUnavailable,
				"Sorry, server can't keep this session.\n"); e != nil {
				return util.ErrWrapper(e, "fail to response session unavailable")
			}
			return nil
		}
		req.SetProxy(superProxy)
		if superProxy != nil { //set up super proxy concurrency limits
			superProxy.AcquireToken()
			defer superProxy.PushBackToken()
		}

		if err = p.do(c, req); err != nil {
			//TODO: should every error close the http connection? @daizong
			return util.ErrWrapper(err, "error HTTP traffic")
		}

		//TODO: test connection close & keep alive @xiangyu
		//TODO: test different kinds of connection types in one TCP: proxyHTTP, proxyHTTPS .... @xiangyu
		if req.ConnectionClose() {
			break
		}
		req.Reset()
		reader.Reset(c)
	}

	return nil
}

func (p *Proxy) do(c net.Conn, req *Request) error {
	// make http client requests
	if !http.IsMethodConnect(req.Method()) {
		return p.proxyHTTP(c, req)
	}

	// TODO: where did I jumper over the rest http headers? @zichao

	// make the tunnel HTTPS requests
	if !p.Handler.ShouldDecryptHost(req.reqLine.HostInfo().Domain()) {
		return p.tunnelHTTPS(c, req)
	}

	return p.decryptHTTPS(c, req)
}

func (p *Proxy) proxyHTTP(c net.Conn, req *Request) error {
	// convert connection into a http response
	writer := p.bufioPool.AcquireWriter(c)
	defer p.bufioPool.ReleaseWriter(writer)
	defer writer.Flush()
	resp := p.respPool.Acquire()
	defer p.respPool.Release(resp)
	if err := resp.WriteTo(writer); err != nil {
		return err
	}

	// set hijacker
	var hijacker Hijacker
	if p.Handler.HijackerPool == nil {
		hijacker = defaultNilHijacker
	} else {
		hijacker = p.Handler.HijackerPool.Get(c.RemoteAddr(), req.reqLine.HostInfo().HostWithPort(),
			req.Method(), req.PathWithQueryFragment())
		defer p.Handler.HijackerPool.Put(hijacker)
	}
	req.SetHijacker(hijacker)
	resp.SetHijacker(hijacker)
	if hijackedRespReader := hijacker.HijackResponse(); hijackedRespReader != nil {
		//TODO: usage refactoring, check the result
		_, _, _, err := p.client.DoFake(req, resp, hijackedRespReader)
		return err
	}

	// make the request
	_, _, _, err := p.client.Do(req, resp)
	return err
}

func (p *Proxy) tunnelHTTPS(c net.Conn, req *Request) error {
	// TODO: add traffic calculation
	_, _, err := p.client.DoRaw(
		c, req.GetProxy(), req.TargetWithPort(),
		func(fail error) error { // on tunnel made, return the tunnel made or failed message
			_, err := sendTunnelMessage(c, fail)
			return err
		},
	)
	return err
}

func (p *Proxy) decryptHTTPS(c net.Conn, req *Request) error {
	// hijack this TLS connection firstly
	hijackedConn, serverName, err := mitm.HijackTLSConnection(
		p.Handler.MITMCertAuthority, c, req.reqLine.HostInfo().Domain(),
		func(fail error) error { // before handshaking with client, return the tunnel made or failed message
			_, err := sendTunnelMessage(c, fail)
			return err
		},
	)
	if err != nil {
		if hijackedConn != nil {
			hijackedConn.Close()
		}
		return err
	}
	//TODO: should reuse this decrypted connection?
	defer hijackedConn.Close()

	// reset request to a new one for hijacked request purpose
	req.Reset()
	hijackedConnreader := p.bufioPool.AcquireReader(hijackedConn)
	defer p.bufioPool.ReleaseReader(hijackedConnreader)
	_, err = req.parseStartLine(hijackedConnreader)
	if err != nil {
		return util.ErrWrapper(err, "fail to read fake tls server request header")
	}
	req.SetTLS(serverName)
	return p.proxyHTTP(c, req)
}

var (
	httpTunnelMadeOKayBytes   = []byte("HTTP/1.1 200 OK\r\n\r\n")
	httpTunnelMadeFailedBytes = []byte("HTTP/1.1 501 Bad Gateway\r\n\r\n")
)

func sendTunnelMessage(c net.Conn, fail error) (int, error) {
	if fail != nil {
		n, err := util.WriteWithValidation(c, httpTunnelMadeFailedBytes)
		err = util.ErrWrapper(fail, "fail to write error message to client with error %s", err)
		return n, err
	}
	return util.WriteWithValidation(c, httpTunnelMadeOKayBytes)
}

func writeFastError(w io.Writer, statusCode int, msg string) error {
	var err error
	_, err = w.Write(http.StatusLine(statusCode))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "Connection: close\r\n"+
		"Date: %s\r\n"+
		"Content-Type: text/plain\r\n"+
		"Content-Length: %d\r\n"+
		"\r\n"+
		"%s",
		servertime.ServerDate(), len(msg), msg)
	return err
}
