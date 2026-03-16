package timerpool

import (
	"testing"
	"time"
)

func TestAcquireAndRelease(t *testing.T) {
	timer := Acquire(20 * time.Millisecond)
	defer Release(timer)

	select {
	case <-timer.C:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timer did not fire")
	}
}

func TestReleaseDrainsExpiredTimer(t *testing.T) {
	timer := Acquire(5 * time.Millisecond)
	select {
	case <-timer.C:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timer did not fire")
	}

	Release(timer)

	reused := Acquire(50 * time.Millisecond)
	defer Release(reused)

	select {
	case <-reused.C:
		t.Fatal("reused timer fired immediately from stale value")
	default:
	}
}

func TestReleaseNil(t *testing.T) {
	Release(nil)
}
