package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/client"
	"github.com/haxii/fastproxy/http"
	"github.com/haxii/fastproxy/server"
	"github.com/haxii/fastproxy/servertime"
	"github.com/haxii/fastproxy/superproxy"
	"github.com/haxii/fastproxy/util"
	"github.com/haxii/fastproxy/x509"
	"github.com/haxii/log"

	proxyhttp "github.com/haxii/fastproxy/proxy/http"
)

// Proxy is a forward proxy that substitutes its own certificate
// for incoming TLS connections in place of the upstream server's
// certificate.
type Proxy struct {
	//BufioPool buffer reader and writer pool
	BufioPool *bufiopool.Pool

	//Client proxy uses a http client to dial a remote host for incoming requests
	Client client.Client

	//proxy logger
	ProxyLogger log.Logger

	//proxy handler
	Handler Handler

	//proxy http requests pool
	reqPool proxyhttp.RequestPool
}

func (p *Proxy) init() error {
	if p.ProxyLogger == nil {
		return errors.New("nil ProxyLogger provided")
	}
	if p.BufioPool == nil {
		return errors.New("nil bufio pool provided")
	}
	if p.Handler.HijackerPool == nil {
		return errors.New("nil hijacker pool provided")
	}
	if p.Handler.ShouldAllowConnection == nil {
		p.Handler.ShouldAllowConnection = func(net.Addr) bool {
			return false
		}
	}
	if p.Handler.ShouldDecryptHost == nil {
		p.Handler.ShouldDecryptHost = func(string) bool {
			return false
		}
	}
	if p.Handler.URLProxy == nil {
		p.Handler.URLProxy = func(hostWithPort string, path []byte) *superproxy.SuperProxy {
			return nil
		}
	}
	if p.Handler.MitmCACert == nil {
		p.Handler.MitmCACert = x509.DefaultMitmCA
	}
	if p.Client.BufioPool == nil {
		p.Client.BufioPool = p.BufioPool
	}

	return nil
}

const proxyManagerLoggerName = "ProxyMNG"

// DefaultConcurrency is the maximum number of concurrent connections
const DefaultConcurrency = 256 * 1024

// Serve serves incoming connections from the given listener.
//
// Serve blocks until the given listener returns permanent error.
func (p *Proxy) Serve(ln net.Listener) error {
	if e := p.init(); e != nil {
		return e
	}

	var lastOverflowErrorTime time.Time
	var lastPerIPErrorTime time.Time
	var c net.Conn
	var err error

	maxWorkersCount := DefaultConcurrency
	wp := &server.WorkerPool{
		WorkerFunc:      p.serveConn,
		MaxWorkersCount: maxWorkersCount,
		Logger:          p.ProxyLogger,
	}
	wp.Start()

	for {
		if c, err = p.acceptConn(ln, &lastPerIPErrorTime); err != nil {
			wp.Stop()
			if err == io.EOF {
				return nil
			}
			return err
		}
		if !wp.Serve(c) {
			p.writeFastError(c, http.StatusServiceUnavailable,
				"The connection cannot be served because Server.Concurrency limit exceeded")
			c.Close()
			if time.Since(lastOverflowErrorTime) > time.Minute {
				p.ProxyLogger.Error(proxyManagerLoggerName, nil,
					"The incoming connection cannot be served, "+
						"because %d concurrent connections are served. "+
						"Try increasing Server.Concurrency", maxWorkersCount)
				lastOverflowErrorTime = servertime.CoarseTimeNow()
			}
			time.Sleep(100 * time.Millisecond)
		}
		c = nil
	}
}

func (p *Proxy) acceptConn(ln net.Listener, lastPerIPErrorTime *time.Time) (net.Conn, error) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if c != nil {
				panic("BUG: net.Listener returned non-nil conn and non-nil error")
			}
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				p.ProxyLogger.Error(proxyManagerLoggerName,
					netErr, "Temporary error when accepting new connections")
				time.Sleep(time.Second)
				continue
			}
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				p.ProxyLogger.Error(proxyManagerLoggerName,
					err, "Permanent error when accepting new connections")
				return nil, err
			}
			return nil, io.EOF
		}
		if c == nil {
			panic("BUG: net.Listener returned (nil, nil)")
		}
		return c, nil
	}
}

func (p *Proxy) serveConn(c net.Conn) error {
	if !p.Handler.ShouldAllowConnection(c.RemoteAddr()) {
		return nil
	}
	//convert c into a http request
	reader := p.BufioPool.AcquireReader(c)
	req := p.reqPool.Acquire()
	releaseReqAndReader := func() {
		p.reqPool.Release(req)
		p.BufioPool.ReleaseReader(reader)
	}

	if err := req.ReadFrom(reader); err != nil {
		releaseReqAndReader()
		return util.ErrWrapper(err, "fail to read http request header")
	}
	if len(req.HostWithPort()) == 0 {
		if e := p.writeFastError(c, http.StatusBadRequest,
			"This is a proxy server. Does not respond to non-proxy requests.\n"); e != nil {
			return util.ErrWrapper(e, "fail to response non-proxy request")
		}
		releaseReqAndReader()
		return nil
	}

	//handle http requests
	if !http.IsMethodConnect(req.Method()) {
		err := p.Handler.handleHTTPConns(c, req,
			p.BufioPool, &p.Client)
		releaseReqAndReader()
		if err != nil {
			return util.ErrWrapper(err, "error HTTP traffic %s ", req.HostWithPort())
		}
		return nil
	}

	//handle https proxy request
	//here I make a copy of the host
	//then release the request immediately
	host := strings.Repeat(req.HostWithPort(), 1)
	releaseReqAndReader()
	//make the requests
	if err := p.Handler.handleHTTPSConns(c, host,
		p.BufioPool, &p.Client); err != nil {
		return util.ErrWrapper(err, "error HTTPS traffic "+host+" ")
	}
	return nil
}

func (p *Proxy) writeFastError(w io.Writer, statusCode int, msg string) error {
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
