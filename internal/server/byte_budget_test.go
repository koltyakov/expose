package server

import (
	"sync"
	"testing"
)

func TestPendingResponseBudgetsCountCapacityAndRollback(t *testing.T) {
	t.Parallel()
	global := &byteBudget{limit: 12}
	sessionA := &byteBudget{limit: 8}
	sessionB := &byteBudget{limit: 8}
	first, second := newPendingRequest(), newPendingRequest()
	first.sessionBudget, first.globalBudget = sessionA, global
	second.sessionBudget, second.globalBudget = sessionB, global
	defer first.discardBody()
	defer second.discardBody()
	sess := &session{}
	chunk := make([]byte, 1, 8)
	if !first.sendBody(sess, chunk, 0) {
		t.Fatal("first chunk should fit")
	}
	if global.used.Load() != 8 || sessionA.used.Load() != 8 {
		t.Fatal("budget counted payload length rather than retained capacity")
	}
	if first.sendBody(sess, []byte("x"), 0) {
		t.Fatal("per-tunnel budget exceeded")
	}
	if second.sendBody(sess, chunk, 0) {
		t.Fatal("global budget exceeded")
	}
	if sessionB.used.Load() != 0 || global.used.Load() != 8 {
		t.Fatal("failed global admission retained a reservation")
	}
	first.abort()
	first.discardBody()
	if !second.sendBody(sess, chunk, 0) {
		t.Fatal("aborted request did not release its budget")
	}
	body, _ := second.bodyStream()
	second.releaseBodyChunk(<-body)
	if global.used.Load() != 0 || sessionA.used.Load() != 0 || sessionB.used.Load() != 0 {
		t.Fatal("consumed response retained a reservation")
	}
	if first.sendBody(sess, chunk, 0) {
		t.Fatal("closed request accepted another chunk")
	}
}

func TestPendingResponseQueueOverflowReleasesReservation(t *testing.T) {
	t.Parallel()
	budget := &byteBudget{limit: 64}
	p := newPendingRequest()
	p.globalBudget = budget
	p.bodyCh = make(chan []byte, 1)
	defer p.discardBody()
	if !p.sendBody(&session{}, []byte("one"), 0) {
		t.Fatal("first send failed")
	}
	if p.sendBody(&session{}, []byte("two"), 0) {
		t.Fatal("full queue accepted another chunk")
	}
	if budget.used.Load() != 3 {
		t.Fatalf("queue overflow retained bytes: %d", budget.used.Load())
	}
	p.discardBody()
	if budget.used.Load() != 0 {
		t.Fatal("discard retained bytes")
	}
}

func TestByteBudgetConcurrentAdmissionIsBounded(t *testing.T) {
	t.Parallel()
	budget := &byteBudget{limit: 64}
	release := make(chan struct{})
	var acquired sync.WaitGroup
	var finished sync.WaitGroup
	acquired.Add(100)
	for range 100 {
		finished.Go(func() {
			ok := budget.acquire(8)
			acquired.Done()
			<-release
			if ok {
				budget.release(8)
			}
		})
	}
	acquired.Wait()
	used := budget.used.Load()
	close(release)
	finished.Wait()
	if used != 64 || budget.used.Load() != 0 {
		t.Fatalf("concurrent admission: peak=%d remaining=%d", used, budget.used.Load())
	}
}
