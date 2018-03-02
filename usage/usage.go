package usage

import "sync/atomic"

type ProxyUsage struct {
	Incoming uint64 //byte size
	Outgoing uint64 //byte size
}

func (u *ProxyUsage) AddIncomingSize(n uint64) {
	atomic.AddUint64(&u.Incoming, n)
}

func (u *ProxyUsage) AddOutgoingSize(n uint64) {
	atomic.AddUint64(&u.Outgoing, n)
}

func (u *ProxyUsage) GetIncomingSize() uint64 {
	return atomic.LoadUint64(&u.Incoming)
}

func (u *ProxyUsage) GetOutgoingSize() uint64 {
	return atomic.LoadUint64(&u.Outgoing)
}
