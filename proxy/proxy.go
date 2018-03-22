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
	"github.com/haxii/fastproxy/util"
	"github.com/haxii/log"
)

// Proxy is a HTTP / HTTPS forward proxy with the ability to
// sniff or modify the forwading traffic
type Proxy struct {
	// server basic connection server used by proxy
	server server.Server

	// MaxClientIdleDuration max idle duration for client connection
	// TODO: http? @daizong refer fasthttp's idle handler
	MaxClientIdleDuration time.Duration

	// Concurrency max simultaneous connections per client
	Concurrency int

	// BufioPool buffer reader and writer pool
	BufioPool *bufiopool.Pool

	// Client proxy uses a http client to dial a remote host for incoming requests
	Client client.Client

	// ProxyLogger proxy error logger
	ProxyLogger log.Logger

	// Handler proxy handler
	Handler Handler

	// proxy http requests pool
	reqPool RequestPool
}

const proxyManagerLoggerName = "ProxyMNG"

// Serve serve on the provided ip address
func (p *Proxy) Serve(addr string) error {
	if p.ProxyLogger == nil {
		return errors.New("nil ProxyLogger provided")
	}
	if p.BufioPool == nil {
		return errors.New("nil bufio pool provided")
	}
	p.Handler.init()
	if p.Client.BufioPool == nil {
		p.Client.BufioPool = p.BufioPool
	}
	p.server.Concurrency = p.Concurrency
	p.server.Name = proxyManagerLoggerName
	p.server.Logger = p.ProxyLogger
	p.server.Handler = p.serveConn
	p.server.OnConcurrencyLimitExceeded = func(c net.Conn) {
		writeFastError(c, http.StatusServiceUnavailable,
			"The connection cannot be served because proxy's concurrency limit exceeded")
	}

	return p.server.ListenAndServe()
}

func (p *Proxy) serveConn(c net.Conn) error {
	if !p.Handler.ShouldAllowConnection(c.RemoteAddr()) {
		return nil
	}
	// convert c into a http request
	reader := p.BufioPool.AcquireReader(c)
	req := p.reqPool.Acquire()
	releaseReqAndReader := func() {
		p.reqPool.Release(req)
		p.BufioPool.ReleaseReader(reader)
	}
	defer releaseReqAndReader()
	var err error
	var rn int

	for {
		if p.MaxClientIdleDuration == 0 {
			rn, err = req.ReadFrom(reader)
		} else {
			idleChan := make(chan struct{})
			go func() {
				rn, err = req.ReadFrom(reader)
				idleChan <- struct{}{}
			}()
			select {
			case <-idleChan:
			case <-time.After(p.MaxClientIdleDuration):
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
		go func() {
			p.Client.Usage.AddIncomingSize(uint64(rn))
		}()

		if len(req.HostInfo().HostWithPort()) == 0 {
			if e := writeFastError(c, http.StatusBadRequest,
				"This is a proxy server. Does not respond to non-proxy requests.\n"); e != nil {
				return util.ErrWrapper(e, "fail to response non-proxy request")
			}
			return nil
		}

		var err error
		var host string
		// handle http requests
		if !http.IsMethodConnect(req.Method()) {
			host = req.HostInfo().HostWithPort()
			err = p.Handler.handleHTTPConns(c, req,
				p.BufioPool, &p.Client, &p.Client.Usage)
			req.Reset()
		} else {
			// some header may not be read, but buffered in reader, such as "Host", "Proxy-Connection",
			// should add the buffered size to incoming size
			go func() {
				p.Client.Usage.AddIncomingSize(uint64(reader.Buffered()))
			}()

			// handle https proxy request
			// here I make a copy of the host
			// then reset the request immediately
			host = strings.Repeat(req.HostInfo().HostWithPort(), 1)
			req.Reset()
			err = p.Handler.handleHTTPSConns(c, host,
				p.BufioPool, &p.Client, &p.Client.Usage, p.MaxClientIdleDuration)
		}

		if err != nil {
			if err == ErrSessionUnavailable {
				if e := writeFastError(c, http.StatusSessionUnavailable,
					"Sorry, server can't keep this session.\n"); e != nil {
					return util.ErrWrapper(e, "fail to response session unavailable")
				}
				return nil
			}
			return util.ErrWrapper(err, "error HTTP traffic %s ", host)
		}

		if req.ConnectionClose() {
			break
		}

		reader.Reset(c)
	}

	return nil
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
