package timerpool

import (
	"sync"
	"time"
)

var pool = sync.Pool{
	New: func() any {
		timer := time.NewTimer(time.Hour)
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		return timer
	},
}

func Acquire(d time.Duration) *time.Timer {
	timer := pool.Get().(*time.Timer)
	timer.Reset(d)
	return timer
}

func Release(timer *time.Timer) {
	if timer == nil {
		return
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	pool.Put(timer)
}
