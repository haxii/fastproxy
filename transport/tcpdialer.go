package transport

import (
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/haxii/fastproxy/servertime"
)

// DialFunc must establish connection to addr.
//
//
// TCP address passed to dialFunc always contains host and port.
// Example TCP addr values:
//
//   - foobar.com:80
//   - foobar.com:443
//   - foobar.com:8080
type DialFunc func(addr string) (net.Conn, error)

// DefaultDialTimeout is timeout used by Dial for establishing TCP connections.
const DefaultDialTimeout = 5 * time.Second

// DefaultMaxDialConcurrency max dial concurrency
const DefaultMaxDialConcurrency = 1000

type Dialer struct {
	MaxDialConcurrency int

	DialTCP  func(addr *net.TCPAddr) (net.Conn, error)
	LookupIP func(host string) ([]net.IP, error)

	dialer      *tcpDialer
	dialMap     map[int]DialFunc
	dialMapLock sync.Mutex

	once sync.Once
}

// dial dials the given TCP addr using tcp4.
//
// This function has the following additional features comparing to net.Dial:
//
//   * It reduces load on DNS resolver by caching resolved TCP addressed
//     for DefaultDNSCacheDuration.
//   * It dials all the resolved TCP addresses in round-robin manner until
//     connection is established. This may be useful if certain addresses
//     are temporarily unreachable.
//   * It returns ErrDialTimeout if connection cannot be established during
//     DefaultDialTimeout seconds. Use DialTimeout for customizing dial timeout.
//
// This dialer is intended for custom code wrapping before passing
// to Client.Dial or HostClient.Dial.
//
// For instance, per-host counters and/or limits may be implemented
// by such wrappers.
//
// The addr passed to the function must contain port. Example addr values:
//
//     * foobar.baz:443
//     * foo.bar:80
//     * aaa.com:8080
func (d *Dialer) Dial(addr string, timeout time.Duration, isTLS bool, tlsConfig *tls.Config) (net.Conn, error) {
	d.once.Do(func() {
		d.dialer = &tcpDialer{
			maxDialConcurrency: d.MaxDialConcurrency,
			dialTCP:            d.DialTCP,
			lookupIP:           d.LookupIP,
		}
		d.dialMap = make(map[int]DialFunc)
	})
	conn, err := d.getDialer(timeout)(addr)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("BUG: DialFunc returned (nil, nil)")
	}
	if isTLS {
		conn = tls.Client(conn, tlsConfig)
	}
	return conn, nil
}

func (d *Dialer) getDialer(timeout time.Duration) DialFunc {
	if timeout <= 0 {
		timeout = DefaultDialTimeout
	}
	timeoutRounded := int(timeout.Seconds()*10 + 9)

	d.dialMapLock.Lock()
	dialer := d.dialMap[timeoutRounded]
	if dialer == nil {
		_dialer := d.dialer
		dialer = _dialer.newDial(timeout)
		d.dialMap[timeoutRounded] = dialer
	}
	d.dialMapLock.Unlock()
	return dialer
}

type tcpDialer struct {
	dialTCP  func(addr *net.TCPAddr) (net.Conn, error)
	lookupIP func(host string) ([]net.IP, error)

	maxDialConcurrency int

	tcpAddrsLock sync.Mutex
	tcpAddrsMap  map[string]*tcpAddrEntry

	concurrencyCh chan struct{}

	once sync.Once
}

// ErrDialTimeout is returned when TCP dialing is timed out.
var ErrDialTimeout = errors.New("dialing to the given TCP address timed out")

func (d *tcpDialer) newDial(timeout time.Duration) DialFunc {
	d.once.Do(func() {
		if d.dialTCP == nil {
			d.dialTCP = func(addr *net.TCPAddr) (net.Conn, error) {
				return net.DialTCP("tcp", nil, addr)
			}
		}
		if d.lookupIP == nil {
			d.lookupIP = net.LookupIP
		}
		if d.maxDialConcurrency <= 0 {
			d.maxDialConcurrency = DefaultMaxDialConcurrency
		}
		d.concurrencyCh = make(chan struct{}, d.maxDialConcurrency)
		d.tcpAddrsMap = make(map[string]*tcpAddrEntry)
		go d.tcpAddrsClean()
	})

	return func(addr string) (net.Conn, error) {
		addrs, idx, err := d.getTCPAddrs(addr)
		if err != nil {
			return nil, err
		}

		var conn net.Conn
		n := uint32(len(addrs))
		deadline := time.Now().Add(timeout)
		for n > 0 {
			conn, err = d.tryDial(&addrs[idx%n], deadline, d.concurrencyCh)
			if err == nil {
				return conn, nil
			}
			if err == ErrDialTimeout {
				return nil, err
			}
			idx++
			n--
		}
		return nil, err
	}
}

func (d *tcpDialer) tryDial(addr *net.TCPAddr, deadline time.Time, concurrencyCh chan struct{}) (net.Conn, error) {
	timeout := -time.Since(deadline)
	if timeout <= 0 {
		return nil, ErrDialTimeout
	}

	select {
	case concurrencyCh <- struct{}{}:
	default:
		tc := servertime.AcquireTimer(timeout)
		isTimeout := false
		select {
		case concurrencyCh <- struct{}{}:
		case <-tc.C:
			isTimeout = true
		}
		servertime.ReleaseTimer(tc)
		if isTimeout {
			return nil, ErrDialTimeout
		}
	}

	timeout = -time.Since(deadline)
	if timeout <= 0 {
		<-concurrencyCh
		return nil, ErrDialTimeout
	}

	chv := dialResultChanPool.Get()
	if chv == nil {
		chv = make(chan dialResult, 1)
	}
	ch := chv.(chan dialResult)
	go func() {
		var dr dialResult
		dr.conn, dr.err = d.dialTCP(addr)
		ch <- dr
		<-concurrencyCh
	}()

	var (
		conn net.Conn
		err  error
	)

	tc := servertime.AcquireTimer(timeout)
	select {
	case dr := <-ch:
		conn = dr.conn
		err = dr.err
		dialResultChanPool.Put(ch)
	case <-tc.C:
		err = ErrDialTimeout
	}
	servertime.ReleaseTimer(tc)

	return conn, err
}

var dialResultChanPool sync.Pool

type dialResult struct {
	conn net.Conn
	err  error
}

type tcpAddrEntry struct {
	addrs    []net.TCPAddr
	addrsIdx uint32

	resolveTime time.Time
	pending     bool
}

// DefaultDNSCacheDuration is the duration for caching resolved TCP addresses
// by Dial* functions.
const DefaultDNSCacheDuration = time.Minute

func (d *tcpDialer) tcpAddrsClean() {
	expireDuration := 2 * DefaultDNSCacheDuration
	for {
		time.Sleep(time.Second)
		t := time.Now()

		d.tcpAddrsLock.Lock()
		for k, e := range d.tcpAddrsMap {
			if t.Sub(e.resolveTime) > expireDuration {
				delete(d.tcpAddrsMap, k)
			}
		}
		d.tcpAddrsLock.Unlock()
	}
}

func (d *tcpDialer) getTCPAddrs(addr string) ([]net.TCPAddr, uint32, error) {
	d.tcpAddrsLock.Lock()
	e := d.tcpAddrsMap[addr]
	if e != nil && !e.pending && time.Since(e.resolveTime) > DefaultDNSCacheDuration {
		e.pending = true
		e = nil
	}
	d.tcpAddrsLock.Unlock()

	if e == nil {
		addrs, err := d.resolveTCPAddrs(addr)
		if err != nil {
			d.tcpAddrsLock.Lock()
			e = d.tcpAddrsMap[addr]
			if e != nil && e.pending {
				e.pending = false
			}
			d.tcpAddrsLock.Unlock()
			return nil, 0, err
		}

		e = &tcpAddrEntry{
			addrs:       addrs,
			resolveTime: time.Now(),
		}

		d.tcpAddrsLock.Lock()
		d.tcpAddrsMap[addr] = e
		d.tcpAddrsLock.Unlock()
	}

	idx := atomic.AddUint32(&e.addrsIdx, 1)
	return e.addrs, idx, nil
}

func (d *tcpDialer) resolveTCPAddrs(addr string) ([]net.TCPAddr, error) {
	host, portS, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portS)
	if err != nil {
		return nil, err
	}

	ips, err := d.lookupIP(host)
	if err != nil {
		return nil, err
	}

	n := len(ips)
	addrs := make([]net.TCPAddr, 0, n)
	for i := 0; i < n; i++ {
		ip := ips[i]
		addrs = append(addrs, net.TCPAddr{
			IP:   ip,
			Port: port,
		})
	}
	if len(addrs) == 0 {
		return nil, errNoDNSEntries
	}
	return addrs, nil
}

var errNoDNSEntries = errors.New("couldn't find DNS entries for the given domain")
