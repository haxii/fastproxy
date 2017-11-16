package servertime

import (
	"sync/atomic"
	"time"
)

func init() {
	refreshServerDate()
	go func() {
		for {
			time.Sleep(time.Second)
			refreshServerDate()
		}
	}()

	t := time.Now().Truncate(time.Second)
	coarseTime.Store(&t)
	go func() {
		for {
			time.Sleep(time.Second)
			t := time.Now().Truncate(time.Second)
			coarseTime.Store(&t)
		}
	}()
}

var serverDate atomic.Value

func refreshServerDate() {
	dst := time.Now().In(time.UTC).AppendFormat(nil, time.RFC1123)
	copy(dst[len(dst)-3:], []byte("GMT"))
	serverDate.Store(dst)
}

var coarseTime atomic.Value

// CoarseTimeNow returns the current time truncated to the nearest second.
//
// This is a faster alternative to time.Now().
func CoarseTimeNow() time.Time {
	tp := coarseTime.Load().(*time.Time)
	return *tp
}

//ServerDate get a server date for http Date header
func ServerDate() interface{} {
	return serverDate.Load()
}
