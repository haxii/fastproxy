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
	"github.com/haxii/fastproxy/usage"
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

	// ServerReadTimeout read timeout for server connection
	ServerReadTimeout time.Duration
	// ServerWriteTimeout write timeout for server connection
	ServerWriteTimeout time.Duration

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

	// SuperProxy default super proxy for connections, can be override if hijacker is not nil
	SuperProxy *superproxy.SuperProxy

	// Dial default dial function for proxy and target host, can be override if hijacker is not nil
	Dial func(addr string) (net.Conn, error)

	// DialTLS default TLS dial function for proxy and target host, can be override if hijacker is not nil
	DialTLS func(addr string, tlsConfig *tls.Config) (net.Conn, error)

	// hijacker pool for making a hijacker for every incoming request
	HijackerPool HijackerPool

	// MITMCertAuthority root certificate authority used for https decryption
	MITMCertAuthority *tls.Certificate

	// Usage usage
	Usage usage.ProxyUsage
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

	return p.server.ListenAndServe()
}

// ShutDown shut down the server, graceful shutdown tobe added
func (p *Proxy) Close() {
	p.server.Close()
}

func (p *Proxy) serveConnOnLimitExceeded(c net.Conn) {
	writeFastError(c, http.StatusServiceUnavailable,
		"The connection cannot be served because proxy's concurrency limit exceeded")
}

func (p *Proxy) serveConn(c net.Conn) error {
	// convert c into a http request
	reader := p.bufioPool.AcquireReader(c)
	req := p.reqPool.Acquire()
	releaseReqAndReader := func() {
		p.reqPool.Release(req)
		p.bufioPool.ReleaseReader(reader)
	}
	defer releaseReqAndReader()
	var (
		rn                    int
		err                   error
		lastReadDeadlineTime  time.Time
		lastWriteDeadlineTime time.Time
	)
	for {
		if p.ServerReadTimeout > 0 {
			lastReadDeadlineTime, err = p.updateReadDeadline(c, servertime.CoarseTimeNow(), lastReadDeadlineTime)
			if err != nil {
				return err
			}
		}

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
		p.Usage.AddIncomingSize(uint64(rn))

		// discard direct HTTP requests
		if len(req.reqLine.HostInfo().HostWithPort()) == 0 {
			if e := writeFastError(c, http.StatusBadRequest,
				"This is a proxy server. Does not respond to non-proxy requests.\n"); e != nil {
				return util.ErrWrapper(e, "fail to response non-proxy request")
			}
			return nil
		}

		if p.ServerWriteTimeout > 0 {
			lastWriteDeadlineTime, err = p.updateWriteDeadline(c, servertime.CoarseTimeNow(), lastWriteDeadlineTime)
		}

		// TODO: super proxy thread handle
		err = p.do(c, req)
		if err != nil && err != io.EOF {
			//TODO: should every error close the http connection? @daizong
			return util.ErrWrapper(err, "proxy error with "+req.reqLine.HostInfo().TargetWithPort())
		}

		if err == io.EOF || req.ConnectionClose() {
			break
		}
		req.Reset()
		reader.Reset(c)
	}

	return nil
}

func (p *Proxy) do(c net.Conn, req *Request) error {
	var hijacker Hijacker
	isHTTPS := http.IsMethodConnect(req.Method())
	// setup request hijacker
	if p.HijackerPool != nil {
		hijacker = p.HijackerPool.Get(c.RemoteAddr(), isHTTPS,
			req.reqLine.HostInfo().Domain(), req.reqLine.HostInfo().Port())
		req.hijacker = hijacker
		defer p.HijackerPool.Put(hijacker)
	}

	// rewrite the host
	if hijacker != nil {
		newHost, newPort := hijacker.RewriteHost()
		if len(newHost) == 0 || len(newPort) == 0 {
			if e := writeFastError(c, http.StatusBadGateway, "Bad Gateway.\n"); e != nil {
				return util.ErrWrapper(e, "fail to response session unavailable")
			}
			return io.EOF
		}
		newHostWithPort := fmt.Sprintf("%s:%s", newHost, newPort)
		if newHostWithPort != req.reqLine.HostInfo().HostWithPort() {
			req.reqLine.ChangeHost(newHostWithPort)
		}
	}

	// make http client requests
	if !isHTTPS {
		return p.proxyHTTP(c, req)
	}

	// peek raw header of the connect request
	if err := req.peekRawHeader(); err != nil {
		return err
	}
	if hijacker != nil {
		if !hijacker.OnConnect(req.header, req.rawHeader) {
			// the hijacker doesn't allow tunnel making request
			if e := writeFastError(c, http.StatusBadGateway, "Bad Gateway.\n"); e != nil {
				return util.ErrWrapper(e, "fail to response session unavailable")
			}
			return io.EOF
		}
	}
	if err := req.discardRawHeader(); err != nil {
		return err
	}

	// setup the SSL bump
	sslBump := false
	if hijacker != nil {
		sslBump = hijacker.SSLBump()
	}
	if sslBump {
		return p.decryptHTTPS(c, req)
	}
	return p.tunnelHTTPS(c, req)
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
	hijacker := req.hijacker
	resp.SetHijacker(hijacker)

	// pre-processing of the request, hijack request if available
	if err := req.PrePare(); err != nil {
		return err
	}
	req.makeDNSLookUpAndSetSuperProxy(p.SuperProxy)
	if p := req.proxy; p != nil {
		p.AcquireToken()
		defer p.PushBackToken()
	}

	if hijacker != nil {
		// block the request if needed
		if hijacker.Block() {
			return writeFastError(c, http.StatusBadGateway, "")
		}
		// hijack the response if needed
		if hijackedRespReader := hijacker.HijackResponse(); hijackedRespReader != nil {
			defer hijackedRespReader.Close()
			reqReadN, _, respN, err := p.client.DoFake(req, resp, hijackedRespReader)
			p.Usage.AddIncomingSize(uint64(reqReadN))
			p.Usage.AddOutgoingSize(uint64(respN))
			return err
		}
	}

	// make the request
	p.setClientDialer(req)
	reqReadN, reqWriteN, respN, err := p.client.Do(req, resp)
	p.Usage.AddIncomingSize(uint64(reqReadN))
	p.Usage.AddOutgoingSize(uint64(respN))
	if req.GetProxy() != nil {
		req.GetProxy().Usage.AddIncomingSize(uint64(respN))
		req.GetProxy().Usage.AddOutgoingSize(uint64(reqWriteN))
	}
	return err
}

func (p *Proxy) decryptHTTPS(c net.Conn, req *Request) error {
	// hijack this TLS connection firstly
	hijackedConn, serverName, err := mitm.HijackTLSConnection(
		p.MITMCertAuthority, c, req.reqLine.HostInfo().Domain(),
		func(fail error) error { // before handshaking with client, return the tunnel made or failed message
			wn, err := sendTunnelMessage(c, fail)
			p.Usage.AddOutgoingSize(uint64(wn))
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

	if req.hijacker != nil {
		serverName = req.hijacker.RewriteTLSServerName(serverName)
	}

	// reset request to a new one for hijacked request purpose
	targetWithPort := req.reqLine.HostInfo().TargetWithPort()
	ip := req.reqLine.HostInfo().IP()
	hijackedConnReader := p.bufioPool.AcquireReader(hijackedConn)
	defer p.bufioPool.ReleaseReader(hijackedConnReader)

	req.reader = nil
	req.reqLine.Reset()
	req.reader = nil
	reqReadNum, err := req.parseStartLine(hijackedConnReader)
	p.Usage.AddIncomingSize(uint64(reqReadNum))
	if err != nil {
		return util.ErrWrapper(err, "fail to read fake tls server request header")
	}
	req.SetTLS(serverName)
	req.reqLine.HostInfo().ParseHostWithPort(targetWithPort, true)
	req.reqLine.HostInfo().SetIP(ip)
	return p.proxyHTTP(hijackedConn, req)
}

func (p *Proxy) tunnelHTTPS(c net.Conn, req *Request) error {
	req.makeDNSLookUpAndSetSuperProxy(p.SuperProxy)
	if p := req.proxy; p != nil {
		p.AcquireToken()
		defer p.PushBackToken()
	}
	if req.hijacker != nil {
		// block the request if needed
		if req.hijacker.Block() {
			return writeFastError(c, http.StatusBadGateway, "")
		}
	}

	p.setClientDialer(req)
	rwReadNum, rwWriteNum, err := p.client.DoRaw(
		c, req.GetProxy(), req.TargetWithPort(),
		func(fail error) error { // on tunnel made, return the tunnel made or failed message
			_, err := sendTunnelMessage(c, fail)
			return err
		},
	)

	p.Usage.AddIncomingSize(uint64(rwReadNum))
	p.Usage.AddOutgoingSize(uint64(rwWriteNum))
	if req.GetProxy() != nil {
		req.GetProxy().Usage.AddIncomingSize(uint64(rwWriteNum))
		req.GetProxy().Usage.AddOutgoingSize(uint64(rwReadNum))
	}
	return err
}

func (p *Proxy) setClientDialer(req *Request) {
	if req.hijacker == nil {
		p.client.DialTLS = p.DialTLS
		p.client.Dial = p.Dial
		return
	}
	p.client.DialTLS = req.hijacker.DialTLS()
	p.client.Dial = req.hijacker.Dial()
}

func (p *Proxy) updateReadDeadline(c net.Conn, currentTime time.Time, lastDeadlineTime time.Time) (time.Time, error) {
	readTimeout := p.ServerReadTimeout

	// Optimization: update read deadline only if more than 25%
	// of the last read deadline exceeded.
	// See https://github.com/golang/go/issues/15133 for details.
	if currentTime.Sub(lastDeadlineTime) > (readTimeout >> 2) {
		if err := c.SetReadDeadline(currentTime.Add(readTimeout)); err != nil {
			return lastDeadlineTime, util.ErrWrapper(err, "BUG: error in SetReadDeadline(%s)", readTimeout)
		}
		lastDeadlineTime = currentTime
	}
	return lastDeadlineTime, nil
}

func (p *Proxy) updateWriteDeadline(c net.Conn, currentTime time.Time, lastDeadlineTime time.Time) (time.Time, error) {
	writeTimeout := p.ServerWriteTimeout
	// Optimization: update write deadline only if more than 25%
	// of the last write deadline exceeded.
	// See https://github.com/golang/go/issues/15133 for details.
	if currentTime.Sub(lastDeadlineTime) > (writeTimeout >> 2) {
		if err := c.SetWriteDeadline(currentTime.Add(writeTimeout)); err != nil {
			return lastDeadlineTime, util.ErrWrapper(err, "BUG: error in SetWriteDeadline(%s)", writeTimeout)
		}
		lastDeadlineTime = currentTime
	}
	return lastDeadlineTime, nil
}

var (
	httpTunnelMadeOKayBytes   = []byte("HTTP/1.1 200 OK\r\n\r\n")
	httpTunnelMadeFailedBytes = []byte("HTTP/1.1 501 Bad Gateway\r\n\r\n")
)

func sendTunnelMessage(c net.Conn, fail error) (int, error) {
	if fail != nil {
		n, err := util.WriteWithValidation(c, httpTunnelMadeFailedBytes)
		if err == nil {
			return n, fail
		}
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
