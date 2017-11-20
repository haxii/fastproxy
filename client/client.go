package client

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/servertime"
	"github.com/haxii/fastproxy/transport"
)

//TODO: should I give each HostClient a bufio pool rather than share one?

// DefaultDialTimeout is timeout used by Dial and DialDualStack
// for establishing TCP connections.
const DefaultDialTimeout = 3 * time.Second

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
	//StartLine 1st line of request
	StartLine() []byte

	//StartLineWithFullURI 1st line of request with full uri,
	//useful for proxy request
	StartLineWithFullURI() []byte

	//WriteHeaderTo read header from request, then Write To buffer IO writer
	WriteHeaderTo(w *bufio.Writer) error

	//WriteBodyTo read body from request, then Write To buffer IO writer
	WriteBodyTo(w *bufio.Writer) error

	// ConnectionClose if the request's "Connection" header value is
	// set as `Close`
	//
	// this determines weather the client reusing the connetions
	ConnectionClose() bool

	//specified in request's start line usually
	IsIdempotent() bool
	IsTLS() bool
	HostWithPort() string
	TLSServerName() string

	//super proxy
	GetProxy() *SuperProxy
}

//Response http response for response
type Response interface {
	//ReadFrom read the http response from the buffer IO reader
	ReadFrom(*bufio.Reader) error

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

	mLock sync.Mutex
	m     map[string]*HostClient
	ms    map[string]*HostClient
}

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

	host := req.HostWithPort()

	isTLS := req.IsTLS()

	startCleaner := false

	c.mLock.Lock()
	m := c.m
	if isTLS {
		m = c.ms
	}
	if m == nil {
		m = make(map[string]*HostClient)
		if isTLS {
			c.ms = m
		} else {
			c.m = m
		}
	}
	hc := m[string(host)]
	if hc == nil {
		hc = &HostClient{
			Addr:          host,
			IsTLS:         isTLS,
			TLSServerName: req.TLSServerName(),
			BufioPool:     c.BufioPool,
			ReadTimeout:   c.ReadTimeout,
			WriteTimeout:  c.WriteTimeout,
			ConnManager: transport.ConnManager{
				MaxConns:            c.MaxConnsPerHost,
				MaxIdleConnDuration: c.MaxIdleConnDuration,
			},
		}
		m[string(host)] = hc
		if len(m) == 1 {
			startCleaner = true
		}
	}
	c.mLock.Unlock()

	if startCleaner {
		go c.mCleaner(m)
	}

	return hc.Do(req, resp)
}

func (c *Client) mCleaner(m map[string]*HostClient) {
	mustStop := false
	for {
		t := time.Now()
		c.mLock.Lock()
		for k, v := range m {
			if t.Sub(v.LastUseTime()) > time.Minute {
				delete(m, k)
			}
		}
		if len(m) == 0 {
			mustStop = true
		}
		c.mLock.Unlock()

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
	// Comma-separated list of upstream HTTP server host addresses,
	// which are passed to Dial in a round-robin manner.
	//
	// Each address may contain port if default dialer is used.
	// For example,
	//
	//    - foobar.com:80
	//    - foobar.com:443
	//    - foobar.com:8080
	Addr string

	// Whether to use TLS (aka SSL or HTTPS) for host connections.
	IsTLS bool

	// Optional TLS config.
	TLSServerName string

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

	addrsLock sync.Mutex
	addrs     []string
	addrIdx   uint32

	tlsConfigMap     map[string]*tls.Config
	tlsConfigMapLock sync.Mutex

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

		if req.IsIdempotent() {
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
	atomic.StoreUint32(&c.lastUseTime, uint32(servertime.CoarseTimeNow().Unix()-startTimeUnix))

	cc, err := c.ConnManager.AcquireConn(c.dialHostHard)
	if err != nil {
		return false, err
	}
	conn := cc.Get()

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

	bw := c.BufioPool.AcquireWriter(conn)
	writeRequest := func() error {
		reqLine := req.StartLine()
		if nw, err := bw.Write(reqLine); err != nil {
			return err
		} else if nw != len(reqLine) {
			return io.ErrShortWrite
		}
		if err := req.WriteHeaderTo(bw); err != nil {
			return err
		}
		return req.WriteBodyTo(bw)
	}
	if e := writeRequest(); e != nil {
		c.BufioPool.ReleaseWriter(bw)
		c.ConnManager.CloseConn(cc)
		return true, e
	}
	err = bw.Flush()
	c.BufioPool.ReleaseWriter(bw)

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
	if err = resp.ReadFrom(br); err != nil {
		c.BufioPool.ReleaseReader(br)
		c.ConnManager.CloseConn(cc)
		return true, err
	}
	c.BufioPool.ReleaseReader(br)

	if resetConnection || req.ConnectionClose() || resp.ConnectionClose() {
		c.ConnManager.CloseConn(cc)
	} else {
		c.ConnManager.ReleaseConn(cc)
	}

	return false, err
}

func (c *HostClient) nextAddr() string {
	c.addrsLock.Lock()
	if c.addrs == nil {
		c.addrs = strings.Split(c.Addr, ",")
	}
	addr := c.addrs[0]
	if len(c.addrs) > 1 {
		addr = c.addrs[c.addrIdx%uint32(len(c.addrs))]
		c.addrIdx++
	}
	c.addrsLock.Unlock()
	return addr
}

func (c *HostClient) dialHostHard() (conn net.Conn, err error) {
	// attempt to dial all the available hosts before giving up.
	c.addrsLock.Lock()
	n := len(c.addrs)
	c.addrsLock.Unlock()

	if n == 0 {
		// It looks like c.addrs isn't initialized yet.
		n = 1
	}

	timeout := c.ReadTimeout + c.WriteTimeout
	if timeout <= 0 {
		timeout = DefaultDialTimeout
	}
	deadline := time.Now().Add(timeout)
	for n > 0 {
		addr := c.nextAddr()
		tlsConfig := c.cachedTLSConfig(addr)
		if c.IsTLS {
			conn, err = transport.DialTLS(addr, tlsConfig)
		} else {
			conn, err = transport.Dial(addr)
		}
		if err == nil {
			return conn, nil
		}
		if time.Since(deadline) >= 0 {
			break
		}
		n--
	}
	return nil, err
}

func (c *HostClient) cachedTLSConfig(addr string) *tls.Config {
	if !c.IsTLS {
		return nil
	}

	c.tlsConfigMapLock.Lock()
	if c.tlsConfigMap == nil {
		c.tlsConfigMap = make(map[string]*tls.Config)
	}
	cfg := c.tlsConfigMap[addr]
	if cfg == nil {
		cfg = newClientTLSConfig(addr, c.TLSServerName)
		c.tlsConfigMap[addr] = cfg
	}
	c.tlsConfigMapLock.Unlock()

	return cfg
}

func newClientTLSConfig(host, serverName string) *tls.Config {
	tlsServerName := func(addr string) string {
		if !strings.Contains(addr, ":") {
			return addr
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return "*"
		}
		return host
	}
	tlsConfig := &tls.Config{}
	tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(0)

	if len(serverName) == 0 {
		hostName := tlsServerName(host)
		if hostName == "*" {
			tlsConfig.InsecureSkipVerify = true
		} else {
			tlsConfig.ServerName = hostName
		}
	} else {
		tlsConfig.ServerName = serverName
	}
	return tlsConfig
}
