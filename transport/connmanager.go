package transport

import (
	"errors"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/haxii/fastproxy/servertime"
)

const (
	// DefaultMaxConnsPerHost is the maximum number of concurrent connections
	// http client may establish per host by default (i.e. if
	// Client.MaxConnsPerHost isn't set).
	DefaultMaxConnsPerHost = 512

	// DefaultMaxIdleConnDuration is the default duration before idle keep-alive
	// connection is closed.
	DefaultMaxIdleConnDuration = 10 * time.Second
)

// ConnManager manages a poll of connections
type ConnManager struct {
	// Maximum number of connections which may be established to all hosts
	// listed in Address
	//
	// DefaultMaxConnsPerHost is used if not set.
	MaxConns int

	// Keep-alive connections are closed after this duration.
	//
	// By default connection duration is unlimited.
	MaxConnDuration time.Duration

	// Idle keep-alive connections are closed after this duration.
	//
	// By default idle connections are closed
	// after DefaultMaxIdleConnDuration.
	MaxIdleConnDuration time.Duration

	connsLock  sync.Mutex
	connsCount int
	conns      []*Conn

	connsCleanerRun bool
}

var (
	// ErrNoFreeConns is returned when no free connections available
	// to the given host.
	//
	// Increase the allowed number of connections per host if you
	// see this error.
	ErrNoFreeConns = errors.New("no free connections available to host")

	// ErrTimeout is returned from timed out calls.
	ErrTimeout = errors.New("timeout")
)

// Dialer returns a connection
type NewConn func() (net.Conn, error)

// AcquireConn acquire a connection
func (c *ConnManager) AcquireConn(dialer NewConn) (*Conn, error) {
	var cc *Conn
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

	conn, err := dialer()
	if err != nil {
		c.decConnsCount()
		return nil, err
	}
	cc = acquireClientConn(conn)

	return cc, nil
}

func (c *ConnManager) connsCleaner() {
	if c.MaxIdleConnDuration <= 0 {
		c.MaxIdleConnDuration = DefaultMaxIdleConnDuration
	}

	var (
		scratch             []*Conn
		maxIdleConnDuration = c.MaxIdleConnDuration
	)
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
			c.CloseConn(cc)
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

// CloseConn close the connection
func (c *ConnManager) CloseConn(cc *Conn) {
	c.decConnsCount()
	cc.c.Close()
	releaseClientConn(cc)
}

func (c *ConnManager) decConnsCount() {
	c.connsLock.Lock()
	c.connsCount--
	c.connsLock.Unlock()
}

// ReleaseConn release the connection back into host connection pool
func (c *ConnManager) ReleaseConn(cc *Conn) {
	go func() { // release the connection in new go routine cause of the delay
		if c.isConnClosedByRemote(cc.c, 10*time.Microsecond) {
			c.CloseConn(cc)
			return
		}
		cc.lastUseTime = servertime.CoarseTimeNow()
		c.connsLock.Lock()
		c.conns = append(c.conns, cc)
		c.connsLock.Unlock()
	}()
}

func (c *ConnManager) isConnClosedByRemote(conn net.Conn, delay time.Duration) bool {
	one := []byte{'1'}
	conn.SetReadDeadline(time.Now().Add(delay))
	if _, err := conn.Read(one); err == io.EOF {
		return true
	}
	var zero time.Time
	conn.SetReadDeadline(zero)
	return false
}

var connPool sync.Pool

func acquireClientConn(conn net.Conn) *Conn {
	v := connPool.Get()
	if v == nil {
		v = &Conn{id: rand.Uint64()}
	}
	cc := v.(*Conn)
	cc.c = conn
	cc.createdTime = servertime.CoarseTimeNow()
	return cc
}

func releaseClientConn(cc *Conn) {
	cc.c = nil
	connPool.Put(cc)
}

// Conn wrapper of net.conn as a manager
type Conn struct {
	c  net.Conn
	id uint64

	createdTime time.Time
	lastUseTime time.Time

	// last read and write deadline time
	LastReadDeadlineTime  time.Time
	LastWriteDeadlineTime time.Time
}

// Get get the net conn in cc
func (cc *Conn) Get() net.Conn {
	return cc.c
}

// ID returns the id for this connection
func (cc *Conn) ID() uint64 {
	return cc.id
}

// CreatedTime get the net conn created time
func (cc *Conn) CreatedTime() time.Time {
	return cc.createdTime
}

// LastUseTime get the net conn last use time
func (cc *Conn) LastUseTime() time.Time {
	return cc.lastUseTime
}
