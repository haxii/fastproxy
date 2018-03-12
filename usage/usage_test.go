package usage

import (
	"testing"
	"time"
)

func TestUsage(t *testing.T) {
	proxyUsage := NewProxyUsage()
	proxyUsage.Start()
	preIncomingSize := 0
	preOutgoingSize := 0
	for i := 1; i < 100; i++ {
		proxyUsage.AddIncomingSize(uint64(i))
		time.Sleep(1 * time.Millisecond)
		if proxyUsage.GetIncomingSize() != uint64(i+preIncomingSize) {
			t.Fatal("IncomingSize count error")
		}
		proxyUsage.AddOutgoingSize(uint64(i))
		time.Sleep(1 * time.Millisecond)
		if proxyUsage.GetOutgoingSize() != uint64(i+preOutgoingSize) {
			t.Fatal("OutgoingSize count error")
		}
		preIncomingSize = int(proxyUsage.GetIncomingSize())
		preOutgoingSize = int(proxyUsage.GetOutgoingSize())
	}
	proxyUsage.Stop()
	if proxyUsage.GetIncomingSize() != 4950 {
		t.Fatal("IncomingSize count error")
	}
	if proxyUsage.GetOutgoingSize() != 4950 {
		t.Fatal("IncomingSize count error")
	}

	proxyUsage.AddIncomingSize(1000)
	if proxyUsage.GetIncomingSize() != 4950 {
		t.Fatal("IncomingSize count error")
	}
	proxyUsage.AddOutgoingSize(1000)
	if proxyUsage.GetOutgoingSize() != 4950 {
		t.Fatal("OutgoingSize count error")
	}

	proxyUsage.Incoming = 0
	proxyUsage.Start()
	proxyUsage.AddIncomingSize(10000000000000000000)
	time.Sleep(1 * time.Millisecond)
	if proxyUsage.GetIncomingSize() != 10000000000000000000 {
		t.Fatal("IncomingSize count error")
	}
}
