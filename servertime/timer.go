package servertime

import (
	"sync"
	"time"
)

func initTimer(t *time.Timer, timeout time.Duration) *time.Timer {
	if t == nil {
		return time.NewTimer(timeout)
	}
	if t.Reset(timeout) {
		panic("BUG: active timer trapped into initTimer()")
	}
	return t
}

func stopTimer(t *time.Timer) {
	if !t.Stop() {
		// Collect possibly added time from the channel
		// if timer has been stopped and nobody collected its' value.
		select {
		case <-t.C:
		default:
		}
	}
}

//AcquireTimer get a timer from pool
func AcquireTimer(timeout time.Duration) *time.Timer {
	v := timerPool.Get()
	if v == nil {
		return time.NewTimer(timeout)
	}
	t := v.(*time.Timer)
	initTimer(t, timeout)
	return t
}

//ReleaseTimer put a timer back into pool
func ReleaseTimer(t *time.Timer) {
	stopTimer(t)
	timerPool.Put(t)
}

var timerPool sync.Pool
