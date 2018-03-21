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
}

//AddIncomingSize adds incoming size
func (u *ProxyUsage) AddIncomingSize(n uint64) {
	atomic.AddUint64(&u.Incoming, n)
}

//AddOutgoingSize adds outgoing size
func (u *ProxyUsage) AddOutgoingSize(n uint64) {
	atomic.AddUint64(&u.Outgoing, n)
}

//GetIncomingSize returns Incoming
func (u *ProxyUsage) GetIncomingSize() uint64 {
	return atomic.LoadUint64(&u.Incoming)
}

//GetOutgoingSize returns Outgoing
func (u *ProxyUsage) GetOutgoingSize() uint64 {
	return atomic.LoadUint64(&u.Outgoing)
}
