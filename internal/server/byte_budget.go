package server

import "sync/atomic"

// byteBudget counts retained buffer capacity rather than payload length. Small
// chunks can still own a full pooled buffer. A zero limit is unlimited for
// manually constructed sessions; production limits are set before publishing.
type byteBudget struct {
	limit int64
	used  atomic.Int64
}

func (b *byteBudget) acquire(n int64) bool {
	if b == nil {
		return true
	}
	for used := b.used.Load(); ; used = b.used.Load() {
		if b.limit > 0 && n > b.limit-used {
			return false
		}
		if b.used.CompareAndSwap(used, used+n) {
			return true
		}
	}
}

func (b *byteBudget) release(n int64) {
	if b != nil {
		b.used.Add(-n)
	}
}
