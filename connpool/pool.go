package connpool

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/haxii/fastproxy/servertime"
)

// DefaultMaxIdleConnDuration is the default duration before idle keep-alive
// connection is closed.
const DefaultMaxIdleConnDuration = 10 * time.Second

// ErrNoFreeConns is returned when no free connections available
// to the given host.
//
// Increase the allowed number of connections per host if you
// see this error.
var ErrNoFreeConns = errors.New("no free connections available to host")

// DefaultMaxConnsPerHost is the maximum number of concurrent connections
// http client may establish per host by default (i.e. if
// Client.MaxConnsPerHost isn't set).
const DefaultMaxConnsPerHost = 512

//CachedConn a caching wrapper of net.conn
type CachedConn struct {
	c net.Conn

	createdTime time.Time
	lastUseTime time.Time
}

//Get get the net.conn for use
func (cc *CachedConn) Get() *net.Conn {
	return &cc.c
}

//CachedConnPool pool of cached net.conn
type CachedConnPool struct {
	// Maximum number of connections which may be established to all hosts
	// listed in Addr.
	//
	// DefaultMaxConnsPerHost is used if not set.
	MaxConns int

	// Idle keep-alive connections are closed after this duration.
	//
	// By default idle connections are closed
	// after DefaultMaxIdleConnDuration.
	MaxIdleConnDuration time.Duration

	connsLock  sync.Mutex
	connsCount int
	conns      []*CachedConn

	connsCleanerRun bool
}

//GetNetConn get a traditional net.conn
type GetNetConn func() (net.Conn, error)

// Get get a cached connection from poll,
//
// if no free conns can be used, poll will fetch a net.Conn from `getNetConn`
// and cache it then return the cached conn
func (c *CachedConnPool) Get(getNetConn GetNetConn) (*CachedConn, error) {
	var cc *CachedConn
	createConn := false
	startCleaner := false

	var n int
	c.connsLock.Lock()
	n = len(c.conns)
	if n == 0 {
		maxConns := c.MaxConns
		if maxConns <= 0 {
			maxConns = DefaultMaxConnsPerHost
		}
		if c.connsCount < maxConns {
			c.connsCount++
			createConn = true
			if !c.connsCleanerRun {
				startCleaner = true
				c.connsCleanerRun = true
			}
		}
	} else {
		n--
		cc = c.conns[n]
		c.conns[n] = nil
		c.conns = c.conns[:n]
	}
	c.connsLock.Unlock()

	if cc != nil {
		return cc, nil
	}
	if !createConn {
		return nil, ErrNoFreeConns
	}

	if startCleaner {
		go c.connsCleaner()
	}

	conn, err := getNetConn()
	if err != nil {
		c.decConnsCount()
		return nil, err
	}
	cc = acquireClientConn(conn)

	return cc, nil
}

//Close close this conn
func (c *CachedConnPool) Close(cc *CachedConn) {
	c.decConnsCount()
	cc.c.Close()
	releaseClientConn(cc)
}

//Release put this cached conn back into pool
func (c *CachedConnPool) Release(cc *CachedConn) {
	cc.lastUseTime = servertime.CoarseTimeNow()
	c.connsLock.Lock()
	c.conns = append(c.conns, cc)
	c.connsLock.Unlock()
}

func (c *CachedConnPool) decConnsCount() {
	c.connsLock.Lock()
	c.connsCount--
	c.connsLock.Unlock()
}

func (c *CachedConnPool) connsCleaner() {
	var (
		scratch             []*CachedConn
		maxIdleConnDuration = c.MaxIdleConnDuration
	)
	if maxIdleConnDuration <= 0 {
		maxIdleConnDuration = DefaultMaxIdleConnDuration
	}
	for {
		currentTime := time.Now()

		// Determine idle connections to be closed.
		c.connsLock.Lock()
		conns := c.conns
		n := len(conns)
		i := 0
		for i < n && currentTime.Sub(conns[i].lastUseTime) > maxIdleConnDuration {
			i++
		}
		scratch = append(scratch[:0], conns[:i]...)
		if i > 0 {
			m := copy(conns, conns[i:])
			for i = m; i < n; i++ {
				conns[i] = nil
			}
			c.conns = conns[:m]
		}
		c.connsLock.Unlock()

		// Close idle connections.
		for i, cc := range scratch {
			c.Close(cc)
			scratch[i] = nil
		}

		// Determine whether to stop the connsCleaner.
		c.connsLock.Lock()
		mustStop := c.connsCount == 0
		if mustStop {
			c.connsCleanerRun = false
		}
		c.connsLock.Unlock()
		if mustStop {
			break
		}

		time.Sleep(maxIdleConnDuration)
	}
}

var generalClientConnPool sync.Pool

func acquireClientConn(conn net.Conn) *CachedConn {
	v := generalClientConnPool.Get()
	if v == nil {
		v = &CachedConn{}
	}
	cc := v.(*CachedConn)
	cc.c = conn
	cc.createdTime = servertime.CoarseTimeNow()
	return cc
}

func releaseClientConn(cc *CachedConn) {
	cc.c = nil
	generalClientConnPool.Put(cc)
}
