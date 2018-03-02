package usage

import "sync/atomic"

const (
	DEFAULT_CHAN_CAP = 1000
)

type ProxyUsage struct {
	Incoming uint64 //byte size
	Outgoing uint64 //byte size

	incomingChan chan uint64
	outgoingChan chan uint64

	done chan struct{}
}

func (u *ProxyUsage) Start() {
	u.incomingChan = make(chan uint64, DEFAULT_CHAN_CAP)
	u.outgoingChan = make(chan uint64, DEFAULT_CHAN_CAP)
	go func() {
		var n uint64
		for {
			select {
			case n = <-u.incomingChan:
				u.Incoming += n
			case n = <-u.outgoingChan:
				u.Outgoing += n
			case <-u.done:
				return
			}
		}
	}()
}

func (u *ProxyUsage) Stop() {
	u.done <- struct{}{}

	close(u.incomingChan)
	close(u.outgoingChan)
	u.incomingChan = nil
	u.outgoingChan = nil
}

func (u *ProxyUsage) AddIncomingSize(n uint64) {
	if u.incomingChan == nil {
		return
	}
	u.incomingChan <- n
}

func (u *ProxyUsage) AddOutgoingSize(n uint64) {
	if u.outgoingChan == nil {
		return
	}
	u.outgoingChan <- n
}

func (u *ProxyUsage) GetIncomingSize() uint64 {
	return atomic.LoadUint64(&u.Incoming)
}

func (u *ProxyUsage) GetOutgoingSize() uint64 {
	return atomic.LoadUint64(&u.Outgoing)
}
