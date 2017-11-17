package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/client"
	"github.com/haxii/fastproxy/header"
	"github.com/haxii/fastproxy/log"
	"github.com/haxii/fastproxy/server"
	"github.com/haxii/fastproxy/servertime"
	"github.com/haxii/fastproxy/x509"
)

//HostFilter host analysis
type HostFilter func(host string) bool

//URLFilter URL analysis
type URLFilter func(uri url.URL) bool

// Proxy is a forward proxy that substitutes its own certificate
// for incoming TLS connections in place of the upstream server's
// certificate.
type Proxy struct {
	//ShouldDecryptHTTPS test if host's https connection should be decrypted
	ShouldDecryptHTTPS HostFilter

	//proxy logger
	ProxyLogger log.Logger

	//client
	client client.Client

	//proxy handler
	handler handler

	//proxy sniffer
	sniffer Sniffer

	//buffer reader and writer pool
	bufioPool bufiopool.Pool
}

// DefaultConcurrency is the maximum number of concurrent connections
const DefaultConcurrency = 256 * 1024

// Serve serves incoming connections from the given listener.
//
// Serve blocks until the given listener returns permanent error.
func (p *Proxy) Serve(ln net.Listener) error {
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
			p.writeFastError(c, header.StatusServiceUnavailable,
				"The connection cannot be served because Server.Concurrency limit exceeded")
			c.Close()
			if time.Since(lastOverflowErrorTime) > time.Minute {
				p.ProxyLogger.Error(nil, "The incoming connection cannot be served, "+
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
				p.ProxyLogger.Error(netErr, "Temporary error when accepting new connections")
				time.Sleep(time.Second)
				continue
			}
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				p.ProxyLogger.Error(err, "Permanent error when accepting new connections")
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
	errorWrapper := func(msg string, err error) error {
		return fmt.Errorf("%s: %s", msg, err)
	}

	//convert c into a http request
	reader := p.bufioPool.AcquireReader(c)
	req := AcquireRequest()
	releaseReqAndReader := func() {
		ReleaseRequest(req)
		p.bufioPool.ReleaseReader(reader)
	}
	if err := req.InitWithProxyReader(reader, p.sniffer); err != nil {
		releaseReqAndReader()
		if err == header.ErrNoHostProvided {
			err = errors.New("client requests a non-proxy request")
			//handle http server request
			if e := p.writeFastError(c,
				header.StatusBadRequest,
				"This is a proxy server. Does not respond to non-proxy requests.\n"); e != nil {
				err = errorWrapper("fail to response non-proxy request ", e)
			}
		}
		return errorWrapper("fail to read http request header", err)
	}

	//get the start line of the http request
	reqLine := req.GetStartLine()

	//handle https proxy request
	if reqLine.IsConnect() {
		//here I make a copy of the host
		//then release the request immediately
		host := strings.Repeat(reqLine.HostWithPort(), 1)
		releaseReqAndReader()
		//make the requests
		var err error
		if p.ShouldDecryptHTTPS(host) {
			err = p.handler.decryptConnect(c, &p.client, host)
		} else {
			err = p.handler.tunnelConnect(&c, host)
		}
		return err
	}

	//convert c into a http response
	writer := p.bufioPool.AcquireWriter(c)
	defer p.bufioPool.ReleaseWriter(writer)
	defer writer.Flush()
	resp := AcquireResponse()
	defer ReleaseResponse(resp)
	if err := resp.InitWithWriter(writer, p.sniffer); err != nil {
		releaseReqAndReader()
		return errorWrapper("fail to init http response header", err)
	}

	var err error
	//handle http proxy request
	if e := p.client.Do(req, resp); e != nil {
		err = errorWrapper("fail to make client request ", e)
	}

	releaseReqAndReader()
	return err
}

func (p *Proxy) writeFastError(w io.Writer, statusCode int, msg string) error {
	var err error
	_, err = w.Write(header.StatusLine(statusCode))
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

//NewSimpleProxy make a simple proxy
func NewSimpleProxy() *Proxy {
	l := &log.DefaultLogger{}

	p := &Proxy{
		handler:            handler{CA: x509.DefaultMitmCA},
		client:             client.Client{},
		sniffer:            NewDefaltLogSniffer(l),
		ShouldDecryptHTTPS: func(string) bool { return true },
		ProxyLogger:        l,
	}
	p.client.BufioPool = &p.bufioPool
	p.handler.bufioPool = &p.bufioPool
	p.handler.sniffer = p.sniffer
	return p
}
