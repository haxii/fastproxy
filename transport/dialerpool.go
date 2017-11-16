package transport

import (
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/haxii/fastproxy/connpool"
	"github.com/haxii/fastproxy/servertime"
)

/*

_WIP_WIP_WIP_WIP_WIP_WIP_WIP_WIP_WIP_WIP_WIP_WIP_WIP_WIP_WIP_WIP_WIP_

Still Working on progress, doNOT use in production mode

use the http client `github.com/haxii/fastproxy/client` insdead

_WIP_WIP_WIP_WIP_WIP_WIP_WIP_WIP_WIP_WIP_WIP_WIP_WIP_WIP_WIP_WIP_WIP_

*/

//HostDialerPool ...
type HostDialerPool struct {
	// Maximum number of connections per each host which may be established.
	//
	// DefaultMaxConnsPerHost is used if not set.
	MaxConnsPerHost int

	// Idle keep-alive connections are closed after this duration.
	//
	// By default idle connections are closed
	// after DefaultMaxIdleConnDuration.
	MaxIdleConnDuration time.Duration

	dialersLock    sync.Mutex
	hostDialers    map[string]*HostDialer
	hostTLSDialers map[string]*HostDialer
}

//Get get cached host dialer for host
func (d *HostDialerPool) Get(host string, isTLS bool,
	serverName string) *HostDialer {
	startCleaner := false

	d.dialersLock.Lock()
	dialers := d.hostDialers
	if isTLS {
		dialers = d.hostTLSDialers
	}
	if dialers == nil {
		dialers = make(map[string]*HostDialer)
		if isTLS {
			d.hostTLSDialers = dialers
		} else {
			d.hostDialers = dialers
		}
	}
	hostDialer := dialers[string(host)]
	if hostDialer == nil {
		hostDialer = newHostDialer(host, isTLS, serverName,
			d.MaxConnsPerHost, d.MaxIdleConnDuration)
		dialers[string(host)] = hostDialer
		if len(dialers) == 1 {
			startCleaner = true
		}
	}
	d.dialersLock.Unlock()

	if startCleaner {
		go d.mCleaner(dialers)
	}

	hostDialer.updateLastUseTime()
	return hostDialer
}

func (d *HostDialerPool) mCleaner(m map[string]*HostDialer) {
	mustStop := false
	for {
		t := time.Now()
		d.dialersLock.Lock()
		for k, v := range m {
			if t.Sub(v.getLastUseTime()) > time.Minute {
				delete(m, k)
			}
		}
		if len(m) == 0 {
			mustStop = true
		}
		d.dialersLock.Unlock()

		if mustStop {
			break
		}
		time.Sleep(10 * time.Second)
	}
}

// HostDialer holds a connection pool for a given host
type HostDialer struct {
	host      string
	isTLS     bool
	tlsConfig *tls.Config

	connPool connpool.CachedConnPool

	lastUseTime uint32
}

//newHostDialer make a new host dialer
func newHostDialer(host string,
	isTLS bool, serverName string,
	maxConnsPerHost int, maxIdleConnDuration time.Duration) *HostDialer {

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
	hd := &HostDialer{
		host:      host,
		isTLS:     isTLS,
		tlsConfig: tlsConfig,
		connPool: connpool.CachedConnPool{
			MaxConns:            maxConnsPerHost,
			MaxIdleConnDuration: maxIdleConnDuration,
		},
	}
	hd.updateLastUseTime()
	return hd
}

var startTimeUnix = time.Now().Unix()

// getLastUseTime returns time the client was last used
func (c *HostDialer) getLastUseTime() time.Time {
	n := atomic.LoadUint32(&c.lastUseTime)
	return time.Unix(startTimeUnix+int64(n), 0)
}

// updateLastUseTime update time the client was last used
func (c *HostDialer) updateLastUseTime() {
	atomic.StoreUint32(&c.lastUseTime,
		uint32(servertime.CoarseTimeNow().Unix()-startTimeUnix))
}

//Dial dial to the host using the given parameters
func (c *HostDialer) Dial() (*connpool.CachedConn, error) {
	return c.connPool.Get(
		func() (net.Conn, error) {
			return dial(c.host, c.isTLS, c.tlsConfig)
		},
	)
}

//Release release the conn got from host dialer
func (c *HostDialer) Release(cc *connpool.CachedConn) {
	c.connPool.Release(cc)
}

//Close close the conn got from host dialer
func (c *HostDialer) Close(cc *connpool.CachedConn) {
	c.connPool.Close(cc)
}
