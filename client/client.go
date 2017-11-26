package client

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/cert"
	"github.com/haxii/fastproxy/servertime"
	"github.com/haxii/fastproxy/superproxy"
	"github.com/haxii/fastproxy/transport"
)

// ErrConnectionClosed may be returned from client methods if the server
// closes connection before returning the first response byte.
//
// If you see this error, then either fix the server by returning
// 'Connection: close' response header before closing the connection
// or add 'Connection: close' request header before sending requests
// to broken server.
var ErrConnectionClosed = errors.New("the server closed connection before returning the first response byte. " +
	"Make sure the server returns 'Connection: close' response header before closing the connection")

//Request http request for request
type Request interface {
	//Method request method in UPPER case
	Method() []byte
	//HostWithPort
	HostWithPort() string
	//Path request relative path
	Path() []byte
	//Protocol HTTP/1.0, HTTP/1.1 etc.
	Protocol() []byte

	//WriteHeaderTo read header from request, then Write To buffer IO writer
	WriteHeaderTo(*bufio.Writer) error

	//WriteBodyTo read body from request, then Write To buffer IO writer
	WriteBodyTo(*bufio.Writer) error

	// ConnectionClose if the request's "Connection" header value is
	// set as `Close`
	//
	// this determines weather the client reusing the connetions
	ConnectionClose() bool

	//specified in request's start line usually
	IsTLS() bool
	TLSServerName() string

	//super proxy
	GetProxy() *superproxy.SuperProxy
}

//Response http response for response
type Response interface {
	//ReadFrom read the http response from the buffer IO reader
	ReadFrom(discardBody bool, br *bufio.Reader) error

	// ConnectionClose if the response's "Connection" header value is
	// set as `Close`
	//
	// this determines weather the client reusing the connetions
	ConnectionClose() bool
}

// Client implements http client.
//
// Copying Client by value is prohibited. Create new instance instead.
//
// It is safe calling Client methods from concurrently running goroutines.
type Client struct {
	// Maximum number of connections per each host which may be established.
	//
	// DefaultMaxConnsPerHost is used if not set.
	MaxConnsPerHost int

	// Idle keep-alive connections are closed after this duration.
	//
	// By default idle connections are closed
	// after DefaultMaxIdleConnDuration.
	MaxIdleConnDuration time.Duration

	BufioPool *bufiopool.Pool

	// Maximum duration for full response reading (including body).
	//
	// By default response read timeout is unlimited.
	ReadTimeout time.Duration

	// Maximum duration for full request writing (including body).
	//
	// By default request write timeout is unlimited.
	WriteTimeout time.Duration

	hostClientsLock sync.Mutex
	//refers to all possibilities of requestType i.e. isTLS x isProxy
	hostClientsList [4]hostClients
}

type hostClients map[string]*HostClient

type requestType int

func (r *requestType) Value() int {
	return int(*r)
}

func parseRequestType(viaProxy, isTLS bool) requestType {
	var rt requestType
	if !viaProxy {
		if !isTLS {
			rt = requestDirectHTTP
		} else {
			rt = requestDirectHTTPS
		}
	} else {
		if !isTLS {
			rt = requestProxyHTTP
		} else {
			rt = requestProxyHTTPS
		}
	}
	return rt
}

const (
	requestDirectHTTP requestType = iota
	requestDirectHTTPS
	requestProxyHTTP
	requestProxyHTTPS
)

// Do performs the given http request and fills the given http response.
//
// The function doesn't follow redirects.
//
// ErrNoFreeConns is returned if all Client.MaxConnsPerHost connections
// to the requested host are busy.
func (c *Client) Do(req Request, resp Response) error {
	if req == nil {
		return errors.New("nil request")
	}
	if resp == nil {
		return errors.New("nil response")
	}
	if c.BufioPool == nil {
		return errors.New("nil buffer io pool")
	}
	//fetch request type
	viaProxy := (req.GetProxy() != nil)
	reqType := parseRequestType(viaProxy, req.IsTLS())

	//get target dialing host with port
	hostWithPort := ""
	if viaProxy {
		hostWithPort = req.GetProxy().HostWithPort()
		if len(hostWithPort) == 0 {
			return errors.New("nil superproxy proxy host provided")
		}
	} else {
		hostWithPort = req.HostWithPort()
		if len(hostWithPort) == 0 {
			return errors.New("nil target host provided")
		}
	}

	startCleaner := false

	//add or get a host client
	c.hostClientsLock.Lock()
	if c.hostClientsList[reqType.Value()] == nil {
		c.hostClientsList[reqType.Value()] =
			make(map[string]*HostClient)
	}
	hostClients := c.hostClientsList[reqType.Value()]
	hc := c.hostClientsList[reqType.Value()][hostWithPort]
	if hc == nil {
		hc = &HostClient{
			BufioPool:    c.BufioPool,
			ReadTimeout:  c.ReadTimeout,
			WriteTimeout: c.WriteTimeout,
			ConnManager: transport.ConnManager{
				MaxConns:            c.MaxConnsPerHost,
				MaxIdleConnDuration: c.MaxIdleConnDuration,
			},
		}
		hostClients[hostWithPort] = hc
		if len(hostClients) == 1 {
			startCleaner = true
		}
	}
	c.hostClientsLock.Unlock()

	if startCleaner {
		go c.mCleaner(hostClients)
	}

	return hc.Do(req, resp)
}

func (c *Client) mCleaner(m map[string]*HostClient) {
	mustStop := false
	for {
		t := time.Now()
		c.hostClientsLock.Lock()
		for k, v := range m {
			if t.Sub(v.LastUseTime()) > time.Minute {
				delete(m, k)
			}
		}
		if len(m) == 0 {
			mustStop = true
		}
		c.hostClientsLock.Unlock()

		if mustStop {
			break
		}
		time.Sleep(10 * time.Second)
	}
}

// HostClient balances http requests among hosts listed in Addr.
//
// HostClient may be used for balancing load among multiple upstream hosts.
// While multiple addresses passed to HostClient.Addr may be used for balancing
// load among them, it would be better using LBClient instead, since HostClient
// may unevenly balance load among upstream hosts.
//
// It is forbidden copying HostClient instances. Create new instances instead.
//
// It is safe calling HostClient methods from concurrently running goroutines.
type HostClient struct {
	// cached TLS server config
	tlsServerConfig *tls.Config

	//TODO: should I give each HostClient a bufio pool rather than share one?
	// BufioPool buffer connection reader & writer pool
	BufioPool *bufiopool.Pool

	// Maximum duration for full response reading (including body).
	//
	// By default response read timeout is unlimited.
	ReadTimeout time.Duration

	// Maximum duration for full request writing (including body).
	//
	// By default request write timeout is unlimited.
	WriteTimeout time.Duration

	//ConnManager manager of the connections
	ConnManager transport.ConnManager

	lastUseTime uint32

	pendingRequests uint64
}

var startTimeUnix = time.Now().Unix()

// LastUseTime returns time the client was last used
func (c *HostClient) LastUseTime() time.Time {
	n := atomic.LoadUint32(&c.lastUseTime)
	return time.Unix(startTimeUnix+int64(n), 0)
}

// Do performs the given http request and sets the corresponding response.
//
// The function doesn't follow redirects.
//
// ErrNoFreeConns is returned if all HostClient.MaxConns connections
// to the host are busy.
func (c *HostClient) Do(req Request, resp Response) error {
	if req == nil {
		return errors.New("nil request")
	}
	if resp == nil {
		return errors.New("nil response")
	}
	if c.BufioPool == nil {
		return errors.New("nil buffer io pool")
	}
	var err error
	var retry bool
	const maxAttempts = 5
	attempts := 0

	atomic.AddUint64(&c.pendingRequests, 1)
	for {
		retry, err = c.do(req, resp)
		if err == nil || !retry {
			break
		}

		if isIdempotent(req.Method()) {
			// Retry non-idempotent requests if the server closes
			// the connection before sending the response.
			//
			// This case is possible if the server closes the idle
			// keep-alive connection on timeout.
			//
			// Apache and Nginx usually do this.
			if err != io.EOF {
				break
			}
		}
		attempts++
		if attempts >= maxAttempts {
			break
		}
	}
	atomic.AddUint64(&c.pendingRequests, ^uint64(0))

	if err == io.EOF {
		err = ErrConnectionClosed
	}
	return err
}

// PendingRequests returns the current number of requests the client
// is executing.
//
// This function may be used for balancing load among multiple HostClient
// instances.
func (c *HostClient) PendingRequests() int {
	return int(atomic.LoadUint64(&c.pendingRequests))
}

func (c *HostClient) do(req Request, resp Response) (bool, error) {
	//set hostclient's last used time
	atomic.StoreUint32(&c.lastUseTime, uint32(servertime.CoarseTimeNow().Unix()-startTimeUnix))

	//analysis request type
	viaProxy := (req.GetProxy() != nil)
	reqType := parseRequestType(viaProxy, req.IsTLS())

	//set https tls config
	if c.tlsServerConfig == nil {
		if reqType == requestDirectHTTPS {
			c.tlsServerConfig = cert.MakeClientTLSConfig(req.HostWithPort(), req.TLSServerName())
		} else if reqType == requestProxyHTTPS {
			c.tlsServerConfig = &tls.Config{
				ClientSessionCache: tls.NewLRUClientSessionCache(0),
				InsecureSkipVerify: true, //TODO: cache every host config in more safe way in a concurrent map
			}
		}
	}

	//get the connection
	dialer := func() (net.Conn, error) {
		switch reqType {
		case requestDirectHTTP:
			return transport.Dial(req.HostWithPort())
		case requestDirectHTTPS:
			return transport.DialTLS(req.HostWithPort(), c.tlsServerConfig)
		case requestProxyHTTP:
			return transport.Dial(req.GetProxy().HostWithPort())
		case requestProxyHTTPS:
			tunnelConn, err := req.GetProxy().MakeHTTPTunnel(c.BufioPool, req.HostWithPort())
			if err != nil {
				return nil, err
			}
			conn := tls.Client(tunnelConn, c.tlsServerConfig)
			return conn, nil
		}
		return nil, errors.New("request type not implemented")
	}
	cc, err := c.ConnManager.AcquireConn(dialer)
	if err != nil {
		return false, err
	}
	conn := cc.Get()

	//pre-setup
	if c.WriteTimeout > 0 {
		// Optimization: update write deadline only if more than 25%
		// of the last write deadline exceeded.
		// See https://github.com/golang/go/issues/15133 for details.
		currentTime := servertime.CoarseTimeNow()
		if currentTime.Sub(cc.LastWriteDeadlineTime) > (c.WriteTimeout >> 2) {
			if err = conn.SetWriteDeadline(currentTime.Add(c.WriteTimeout)); err != nil {
				c.ConnManager.CloseConn(cc)
				return true, err
			}
			cc.LastWriteDeadlineTime = currentTime
		}
	}
	resetConnection := false
	if c.ConnManager.MaxConnDuration > 0 &&
		time.Since(cc.CreatedTime()) > c.ConnManager.MaxConnDuration &&
		!req.ConnectionClose() {
		resetConnection = true
	}

	//write request
	bw := c.BufioPool.AcquireWriter(conn)
	writeRequest := func() error {
		//start line
		if reqType == requestProxyHTTP {
			writeRequestLine(bw, true, req.Method(),
				req.HostWithPort(), req.Path(), req.Protocol())
		} else {
			writeRequestLine(bw, false, req.Method(),
				req.HostWithPort(), req.Path(), req.Protocol())
		}

		//auth header if needed
		if reqType == requestProxyHTTP {
			if authHeader := req.GetProxy().AuthHeaderWithCRLF(); authHeader != nil {
				if nw, err := bw.Write(authHeader); err != nil {
					return err
				} else if nw != len(authHeader) {
					return io.ErrShortWrite
				}
			}
		}
		//other request headers
		if err := req.WriteHeaderTo(bw); err != nil {
			return err
		}
		//do not read contents for get and head
		if isHead(req.Method()) || isGet(req.Method()) {
			return nil
		}
		//request body
		return req.WriteBodyTo(bw)
	}
	if e := writeRequest(); e != nil {
		c.BufioPool.ReleaseWriter(bw)
		c.ConnManager.CloseConn(cc)
		return true, e
	}
	err = bw.Flush()
	c.BufioPool.ReleaseWriter(bw)

	//get response
	if c.ReadTimeout > 0 {
		// Optimization: update read deadline only if more than 25%
		// of the last read deadline exceeded.
		// See https://github.com/golang/go/issues/15133 for details.
		currentTime := servertime.CoarseTimeNow()
		if currentTime.Sub(cc.LastReadDeadlineTime) > (c.ReadTimeout >> 2) {
			if err = conn.SetReadDeadline(currentTime.Add(c.ReadTimeout)); err != nil {
				c.ConnManager.CloseConn(cc)
				return true, err
			}
			cc.LastReadDeadlineTime = currentTime
		}
	}
	br := c.BufioPool.AcquireReader(conn)
	if err = resp.ReadFrom(isHead(req.Method()), br); err != nil {
		c.BufioPool.ReleaseReader(br)
		c.ConnManager.CloseConn(cc)
		return true, err
	}
	c.BufioPool.ReleaseReader(br)

	//release or close connection
	if viaProxy || resetConnection || req.ConnectionClose() || resp.ConnectionClose() {
		c.ConnManager.CloseConn(cc)
	} else {
		c.ConnManager.ReleaseConn(cc)
	}

	return false, err
}
