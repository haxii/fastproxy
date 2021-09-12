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
	"github.com/haxii/fastproxy/bytebufferpool"
	"github.com/haxii/fastproxy/servertime"
	"github.com/haxii/fastproxy/superproxy"
	"github.com/haxii/fastproxy/transport"
	"github.com/haxii/fastproxy/util"
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

// Request http request used for client
type Request interface {
	// Method request method in UPPER case
	Method() []byte
	// TargetWithPort, expected ip with port, if not, domain with port
	TargetWithPort() string
	// Path request relative path
	PathWithQueryFragment() []byte
	// Protocol HTTP/1.0, HTTP/1.1 etc.
	Protocol() []byte

	// PrePare request preparation, called before connection is made
	PrePare() error

	// WriteHeaderTo read header from request, then Write To buffer IO writer
	WriteHeaderTo(*bufio.Writer) (readNum int, writeNum int, err error)

	// WriteBodyTo read body from request, then Write To buffer IO writer
	WriteBodyTo(*bufio.Writer) (int, error)

	// ConnectionClose if the request's "Connection" header value is
	// set as `Close`
	//
	// this determines weather the client reusing the connections
	ConnectionClose() bool

	// specified in request's start line usually
	IsTLS() bool
	TLSServerName() string

	// super proxy
	GetProxy() *superproxy.SuperProxy
}

// Response http response used for client
type Response interface {
	// ReadFrom read the http response from the buffer IO reader
	ReadFrom(discardBody bool, br *bufio.Reader) (int, error)

	// ConnectionClose if the response's "Connection" header value is
	// set as `Close`
	//
	// this determines whether the client reusing the connections
	ConnectionClose() bool
}

// Client implements http client.
//
// Copying Client by value is prohibited. Create new instance instead.
//
// It is safe calling Client methods from concurrently running go routines.
type Client struct {
	// Dialer
	Dial    func(addr string) (net.Conn, error)
	DialTLS func(addr string, tlsConfig *tls.Config) (net.Conn, error)

	// Maximum number of connections per each host which may be established.
	//
	// DefaultMaxConnsPerHost is used if not set.
	MaxConnsPerHost int

	// Idle keep-alive connections are closed after this duration.
	//
	// By default idle connections are closed after DefaultMaxIdleConnDuration.
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
	// host clients pool, separate common and TLS clients
	hostClients    map[string]*HostClient
	hostTLSClients map[string]*HostClient
}

var (
	errNilReq            = errors.New("nil request")
	errNilResp           = errors.New("nil response")
	errNilFakeResp       = errors.New("nil fake response")
	errNilBufioPool      = errors.New("nil buffer io pool")
	errNilReadWriter     = errors.New("nil read writer provided")
	errNilTargetHost     = errors.New("nil target host provided")
	errNilSuperProxyHost = errors.New("nil super proxy host provided")
)

// DoFake make a client request by giving a faked response
func (c *Client) DoFake(req Request, resp Response, fakeRespReader io.Reader) error {
	writeReqToDevNull := func(req Request) error {
		devNullBufferedWriter := c.BufioPool.AcquireWriter(defaultDevNullWriter)
		defer c.BufioPool.ReleaseWriter(devNullBufferedWriter)
		if _, _, err := req.WriteHeaderTo(devNullBufferedWriter); err != nil {
			return err
		}
		_, err := req.WriteBodyTo(devNullBufferedWriter)
		return err
	}

	if req == nil {
		return errNilReq
	}
	if resp == nil {
		return errNilResp
	}
	if fakeRespReader == nil {
		return errNilFakeResp
	}

	if err := writeReqToDevNull(req); err != nil {
		return err
	}
	bufFakeRespReader := c.BufioPool.AcquireReader(fakeRespReader)
	defer c.BufioPool.ReleaseReader(bufFakeRespReader)
	_, err := resp.ReadFrom(false, bufFakeRespReader)
	return err
}

// DoRaw make simple raw traffic forwarding
func (c *Client) DoRaw(rw io.ReadWriter, sProxy *superproxy.SuperProxy,
	targetWithPort string, onTunnelMade func(error) error) (rwReadNum, rwWriteNum int64, err error) {
	//TODO: TEST DoRaw, Do and DoFake with the same super proxy
	if rw == nil {
		return 0, 0, onTunnelMade(errNilReadWriter)
	}
	connectHostWithPort := targetWithPort
	isConnectHostTLS := false
	if sProxy != nil {
		connectHostWithPort = sProxy.HostWithPort()
		if len(connectHostWithPort) == 0 {
			return 0, 0, onTunnelMade(errNilSuperProxyHost)
		}
		isConnectHostTLS = sProxy.GetProxyType() == superproxy.ProxyTypeHTTPS
	}
	return c.getHostClient(connectHostWithPort,
		isConnectHostTLS).DoRaw(rw, sProxy, targetWithPort, onTunnelMade)
}

// Do performs the given http request and fills the given http response.
//
// The function doesn't follow redirects.
//
// ErrNoFreeConns is returned if all Client.MaxConnsPerHost connections
// to the requested host are busy.
func (c *Client) Do(req Request, resp Response) error {
	if req == nil {
		return errNilReq
	}
	if resp == nil {
		return errNilResp
	}
	if c.BufioPool == nil {
		return errNilBufioPool
	}

	connectHostWithPort := ""
	isConnectHostTLS := false
	if sProxy := req.GetProxy(); sProxy != nil {
		connectHostWithPort = req.GetProxy().HostWithPort()
		if len(connectHostWithPort) == 0 {
			return errNilSuperProxyHost
		}
		isConnectHostTLS = (sProxy.GetProxyType() == superproxy.ProxyTypeHTTPS)
	} else {
		connectHostWithPort = req.TargetWithPort()
		if len(connectHostWithPort) == 0 {
			return errNilTargetHost
		}
		isConnectHostTLS = req.IsTLS()
	}

	return c.getHostClient(connectHostWithPort, isConnectHostTLS).Do(req, resp)
}

// getHostClient get a host client with providing the host to connect
// and whether it supports TLS. For a direct connection, connectHostWithPort
// is the target server. For a proxy connection, connectHostWithPort is the proxy server
func (c *Client) getHostClient(connectHostWithPort string,
	isConnectHostTLS bool) *HostClient {
	startCleaner := false

	// add or get a host client
	c.hostClientsLock.Lock()
	var hostClients map[string]*HostClient
	if isConnectHostTLS {
		if c.hostTLSClients == nil {
			c.hostTLSClients = make(map[string]*HostClient)
		}
		hostClients = c.hostTLSClients
	} else {
		if c.hostClients == nil {
			c.hostClients = make(map[string]*HostClient)
		}
		hostClients = c.hostClients
	}
	hc := hostClients[connectHostWithPort]
	if hc == nil {
		hc = &HostClient{
			Dial:         c.Dial,
			DialTLS:      c.DialTLS,
			BufioPool:    c.BufioPool,
			ReadTimeout:  c.ReadTimeout,
			WriteTimeout: c.WriteTimeout,
			ConnManager: transport.ConnManager{
				MaxConns:            c.MaxConnsPerHost,
				MaxIdleConnDuration: c.MaxIdleConnDuration,
			},
		}
		hostClients[connectHostWithPort] = hc
		if len(hostClients) == 1 {
			startCleaner = true
		}
	}
	c.hostClientsLock.Unlock()

	if startCleaner {
		go c.mCleaner(hostClients)
	}
	return hc
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
// It is safe calling HostClient methods from concurrently running go routines.
type HostClient struct {
	lastUseTime     uint64
	pendingRequests uint64

	// Dialer
	Dial    func(addr string) (net.Conn, error)
	DialTLS func(addr string, tlsConfig *tls.Config) (net.Conn, error)

	// cached TLS server config
	tlsServerConfig *tls.Config

	// TODO: should I give each HostClient a bufio pool rather than share one?
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

	// ConnManager manager of the connections
	ConnManager transport.ConnManager
}

var startTimeUnix = time.Now().Unix()

// LastUseTime returns time the client was last used
func (c *HostClient) LastUseTime() time.Time {
	n := atomic.LoadUint64(&c.lastUseTime)
	return time.Unix(startTimeUnix+int64(n), 0)
}

// DoRaw make simple raw traffic forwarding
func (c *HostClient) DoRaw(rw io.ReadWriter, superProxy *superproxy.SuperProxy,
	targetWithPort string, onTunnelMade func(error) error) (rwReadNum, rwWriteNum int64, err error) {
	// set hostClient's last used time
	atomic.StoreUint64(&c.lastUseTime, uint64(servertime.CoarseTimeNow().Unix()-startTimeUnix))

	// retrieve a connection from pool
	var cc *transport.Conn
	var netConn net.Conn
	if superProxy == nil {
		if c.Dial != nil {
			netConn, err = c.Dial(targetWithPort)
		} else {
			netConn, err = transport.Dial(targetWithPort)
		}
	} else {
		netConn, err = superProxy.MakeTunnel(c.Dial, c.DialTLS, c.BufioPool, targetWithPort)
	}
	if err != nil {
		return 0, 0, onTunnelMade(err)
	}
	cc, err = c.ConnManager.AcquireConn(dialerWrapper(netConn, err))
	if err != nil {
		return 0, 0, onTunnelMade(err)
	}
	if onTunnelMade != nil {
		if err := onTunnelMade(nil); err != nil {
			return 0, 0, err
		}
	}

	conn := cc.Get()

	if c.ReadTimeout > 0 {
		// Optimization: update read deadline only if more than 25%
		// of the last read deadline exceeded.
		// See https:// github.com/golang/go/issues/15133 for details.
		currentTime := servertime.CoarseTimeNow()
		if currentTime.Sub(cc.LastReadDeadlineTime) > (c.ReadTimeout >> 2) {
			if err = conn.SetReadDeadline(currentTime.Add(c.ReadTimeout)); err != nil {
				c.ConnManager.CloseConn(cc)
				return rwReadNum, rwWriteNum, err
			}
			cc.LastReadDeadlineTime = currentTime
		}
	}

	if c.WriteTimeout > 0 {
		// Optimization: update write deadline only if more than 25%
		// of the last write deadline exceeded.
		// See https:// github.com/golang/go/issues/15133 for details.
		currentTime := servertime.CoarseTimeNow()
		if currentTime.Sub(cc.LastWriteDeadlineTime) > (c.WriteTimeout >> 2) {
			if err = conn.SetWriteDeadline(currentTime.Add(c.WriteTimeout)); err != nil {
				c.ConnManager.CloseConn(cc)
				return rwReadNum, rwWriteNum, err
			}
			cc.LastWriteDeadlineTime = currentTime
		}
	}
	// forward incoming connection to destination tunnel
	errChan := make(chan error, 2)
	go func() {
		_, readErr := transport.Forward(conn, rw, c.ConnManager.MaxIdleConnDuration)
		errChan <- readErr
	}()
	go func() {
		_, writeErr := transport.Forward(rw, conn, c.ConnManager.MaxIdleConnDuration)
		errChan <- writeErr
	}()
	select {
	case err = <-errChan:
		if err != nil {
			err = util.ErrWrapper(err, "error occurred when tunneling")
		}
	}

	//TODO: should reuse these connections????? only close socks5 connections? more tests?
	c.ConnManager.CloseConn(cc)
	return
}

// Do performs the given http request and sets the corresponding response.
//
// The function doesn't follow redirects.
//
// ErrNoFreeConns is returned if all HostClient.MaxConns connections
// to the host are busy.
func (c *HostClient) Do(req Request, resp Response) (err error) {
	if req == nil {
		return errors.New("nil request")
	}
	if resp == nil {
		return errors.New("nil response")
	}
	if c.BufioPool == nil {
		return errors.New("nil buffer io pool")
	}
	const maxAttempts = 5
	attempts := 0

	atomic.AddUint64(&c.pendingRequests, 1)
	buffer := bytebufferpool.Get()
	var retry bool
	for {
		retry, err = c.do(req, resp, buffer)
		if err == nil || !retry {
			break
		}

		if !isHeadOrGet(req.Method()) {
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
	bytebufferpool.Put(buffer)
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

var errDialEOF = errors.New("dial EOF")

func (c *HostClient) do(req Request, resp Response,
	reqCacheForRetry *bytebufferpool.ByteBuffer) (retry bool, e error) {
	// set hostClient's last used time
	atomic.StoreUint64(&c.lastUseTime, uint64(servertime.CoarseTimeNow().Unix()-startTimeUnix))

	// analysis request type
	viaProxy := req.GetProxy() != nil

	// get the connection
	var cc *transport.Conn
	var err error

	cc, err = c.ConnManager.AcquireConn(c.makeDialer(req.GetProxy(),
		req.TargetWithPort(), req.IsTLS(), req.TLSServerName()))

	redialCount := 0
	for err == io.EOF && redialCount < 3 {
		redialCount++
		time.Sleep(time.Duration(redialCount*300) * time.Millisecond)
		cc, err = c.ConnManager.AcquireConn(c.makeDialer(req.GetProxy(),
			req.TargetWithPort(), req.IsTLS(), req.TLSServerName()))
	}
	if err != nil {
		if err == io.EOF {
			err = errDialEOF
		}
		return false, err
	}
	conn := cc.Get()

	// pre-setup
	if c.WriteTimeout > 0 {
		// Optimization: update write deadline only if more than 25%
		// of the last write deadline exceeded.
		// See https:// github.com/golang/go/issues/15133 for details.
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

	// write request
	shouldCacheReqForRetry := (reqCacheForRetry != nil) && isHeadOrGet(req.Method())
	isCachedReqAvailable := func() bool { return shouldCacheReqForRetry && (reqCacheForRetry.Len() > 0) }
	if (!shouldCacheReqForRetry) || (!isCachedReqAvailable()) {
		// determine where the parsed request should write to
		var reqWriteToTarget io.Writer
		if shouldCacheReqForRetry {
			reqWriteToTarget = reqCacheForRetry
		} else {
			reqWriteToTarget = conn
		}
		if err = c.readFromReqAndWriteToIOWriter(req, reqWriteToTarget); err != nil {
			if shouldCacheReqForRetry {
				reqCacheForRetry.Reset()
			}
			c.ConnManager.CloseConn(cc)
			// cannot even read a complete request, do NOT retry
			return false, err
		}
	}
	if isCachedReqAvailable() {
		// write the cached http requests to conn
		if _, err = c.writeData(reqCacheForRetry.Bytes(), conn); err != nil {
			c.ConnManager.CloseConn(cc)
			return true, err
		}
	}

	// get response
	if c.ReadTimeout > 0 {
		// Optimization: update read deadline only if more than 25%
		// of the last read deadline exceeded.
		// See https:// github.com/golang/go/issues/15133 for details.
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
	// read a byte from response to test if the connection has been closed by remote
	if b, err := br.Peek(1); err != nil {
		if err == io.EOF {
			return true, io.EOF
		}
		return false, err
	} else if len(b) == 0 {
		return true, io.EOF
	}

	if _, err = resp.ReadFrom(isHead(req.Method()), br); err != nil {
		c.BufioPool.ReleaseReader(br)
		c.ConnManager.CloseConn(cc)
		return false, err
	}
	c.BufioPool.ReleaseReader(br)

	// release or close connection
	if viaProxy || resetConnection || req.ConnectionClose() || resp.ConnectionClose() {
		//TODO: reuse super proxy connections
		c.ConnManager.CloseConn(cc)
	} else {
		c.ConnManager.CloseConn(cc)
	}

	return false, err
}

func (c *HostClient) writeData(data []byte, w io.Writer) (int, error) {
	bw := c.BufioPool.AcquireWriter(w)
	defer c.BufioPool.ReleaseWriter(bw)
	wn, err := bw.Write(data)
	if err != nil {
		return 0, err
	} else if wn != len(data) {
		return 0, io.ErrShortWrite
	}
	return wn, bw.Flush()
}

func (c *HostClient) readFromReqAndWriteToIOWriter(req Request, w io.Writer) (err error) {
	bw := c.BufioPool.AcquireWriter(w)
	defer c.BufioPool.ReleaseWriter(bw)
	isReqProxyHTTP := parseRequestType(req.GetProxy(), req.IsTLS()) == requestProxyHTTP
	// start line
	if isReqProxyHTTP {
		_, err = writeRequestLine(bw, true, req.Method(),
			req.TargetWithPort(), req.PathWithQueryFragment(), req.Protocol())
	} else {
		_, err = writeRequestLine(bw, false, req.Method(),
			"", req.PathWithQueryFragment(), req.Protocol())
	}
	if err != nil {
		return
	}

	// auth header if needed
	if isReqProxyHTTP {
		if authHeader := req.GetProxy().HTTPProxyAuthHeaderWithCRLF(); authHeader != nil {
			if nw, err := bw.Write(authHeader); err != nil {
				return err
			} else if nw != len(authHeader) {
				return io.ErrShortWrite
			}
		}
	}
	// other request headers
	if _, _, err := req.WriteHeaderTo(bw); err != nil {
		return err
	}

	// do not read contents for get and head
	if isHeadOrGet(req.Method()) {
		return bw.Flush()
	}
	// request body
	if _, err := req.WriteBodyTo(bw); err != nil {
		return err
	}

	return bw.Flush()
}
