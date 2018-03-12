package usage

import (
	"sync/atomic"
)

const (
	// DefaultChanCap ...
	DefaultChanCap = 1000
)

// ProxyUsage a struct for counting the size of the data incoming and outgoing
type ProxyUsage struct {
	Incoming uint64 //byte size
	Outgoing uint64 //byte size

	incomingChan chan uint64
	outgoingChan chan uint64

	stop chan struct{}
}

//NewProxyUsage returns a ProxyUsage after Start.
func NewProxyUsage() *ProxyUsage {
	proxy := &ProxyUsage{}
	proxy.Start()
	return proxy
}

//Start inits chans and starts a goroutine to receive data
func (u *ProxyUsage) Start() {
	u.incomingChan = make(chan uint64, DefaultChanCap)
	u.outgoingChan = make(chan uint64, DefaultChanCap)
	u.stop = make(chan struct{})
	go func() {
		defer func() {
			recover()
		}()

		var n uint64
		for {
			select {
			case n = <-u.incomingChan:
				u.Incoming += n
			case n = <-u.outgoingChan:
				u.Outgoing += n
			case <-u.stop:
				return
			}
		}
	}()
}

//Stop closes chans and sets nil
func (u *ProxyUsage) Stop() {
	close(u.stop)
	close(u.incomingChan)
	close(u.outgoingChan)
	u.incomingChan = nil
	u.outgoingChan = nil
	u.stop = nil
}

//AddIncomingSize sends size to incomingChan
func (u *ProxyUsage) AddIncomingSize(n uint64) {
	if u.incomingChan == nil {
		return
	}
	u.incomingChan <- n
}

//AddOutgoingSize sends size to outgoingChan
func (u *ProxyUsage) AddOutgoingSize(n uint64) {
	if u.outgoingChan == nil {
		return
	}
	u.outgoingChan <- n
}

//GetIncomingSize returns Incoming
func (u *ProxyUsage) GetIncomingSize() uint64 {
	return atomic.LoadUint64(&u.Incoming)
}

//GetOutgoingSize returns Outgoing
func (u *ProxyUsage) GetOutgoingSize() uint64 {
	return atomic.LoadUint64(&u.Outgoing)
}
