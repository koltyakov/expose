package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestPendingResponseQueueWrapAndGrowthPreserveOrder(t *testing.T) {
	t.Parallel()
	pending := newPendingRequest()
	budget := &byteBudget{limit: 1 << 20}
	pending.globalBudget = budget
	defer pending.discardBody()
	enqueue := func(i int) {
		t.Helper()
		if err := pending.sendBody(fmt.Appendf(make([]byte, 0, 4096), "%03d", i)); err != nil {
			t.Fatal(err)
		}
	}
	consume := func(i int) {
		t.Helper()
		chunk, done := pending.nextBodyChunk()
		if done || string(chunk) != fmt.Sprintf("%03d", i) {
			t.Fatalf("chunk %d = %q, done=%v", i, chunk, done)
		}
		pending.releaseBodyChunk(chunk)
	}
	for i := range 12 {
		enqueue(i)
	}
	for i := range 8 {
		consume(i)
	}
	for i := 12; i < 80; i++ {
		enqueue(i)
	}
	pending.finish()
	for i := 8; i < 80; i++ {
		consume(i)
	}
	if chunk, done := pending.nextBodyChunk(); chunk != nil || !done {
		t.Fatalf("completed queue = %q, done=%v", chunk, done)
	}
	if budget.used.Load() != 0 || pending.bodyQueue != nil {
		t.Fatal("drained queue retained its budget or oversized backing array")
	}
}

func TestPendingResponseQueueWakeupsAndEmptyFrames(t *testing.T) {
	t.Parallel()
	pending := newPendingRequest()
	budget := &byteBudget{limit: 4096}
	pending.globalBudget = budget
	defer pending.discardBody()
	ready, _ := pending.bodyStream()
	if err := pending.sendBody(make([]byte, 0, 4096)); err != nil {
		t.Fatal(err)
	}
	if budget.used.Load() != 0 || pending.bodyQueue != nil || len(ready) != 0 {
		t.Fatal("empty frame consumed budget, queue storage, or a wakeup")
	}
	for round := range 3 {
		for range 2 {
			if err := pending.sendBody([]byte("event")); err != nil {
				t.Fatal(err)
			}
		}
		if len(ready) != 1 {
			t.Fatalf("round %d: queue notifications were not coalesced", round)
		}
		<-ready
		for range 2 {
			chunk, done := pending.nextBodyChunk()
			if done || string(chunk) != "event" {
				t.Fatalf("unexpected chunk %q, done=%v", chunk, done)
			}
			pending.releaseBodyChunk(chunk)
		}
		if chunk, done := pending.nextBodyChunk(); chunk != nil || done {
			t.Fatalf("open empty queue = %q, done=%v", chunk, done)
		}
	}
	if budget.used.Load() != 0 {
		t.Fatal("consumed frames retained their reservations")
	}
}

func TestPendingResponseQueueFinishSerializesAdmission(t *testing.T) {
	t.Parallel()
	for range 100 {
		pending := newPendingRequest()
		budget := &byteBudget{limit: 4096}
		pending.globalBudget = budget
		start := make(chan struct{})
		admission := make(chan error, 1)
		var workers sync.WaitGroup
		workers.Go(func() { <-start; admission <- pending.sendBody([]byte("last")) })
		workers.Go(func() { <-start; pending.finish() })
		close(start)
		workers.Wait()
		err := <-admission
		chunk, done := pending.nextBodyChunk()
		switch err {
		case nil:
			if done || string(chunk) != "last" {
				t.Fatalf("clean end overtook accepted chunk: %q, done=%v", chunk, done)
			}
			pending.releaseBodyChunk(chunk)
		case errResponseClosed:
			if chunk != nil || !done {
				t.Fatal("closed queue retained a rejected chunk")
			}
		default:
			t.Fatal(err)
		}
		if chunk, done := pending.nextBodyChunk(); chunk != nil || !done {
			t.Fatal("finished queue remained open")
		}
		if err := pending.sendBody([]byte("late")); err != errResponseClosed {
			t.Fatalf("late admission = %v, want closed", err)
		}
		if budget.used.Load() != 0 {
			t.Fatal("concurrent completion retained budget")
		}
	}
}

type pendingResponseGateWriter struct {
	*httptest.ResponseRecorder
	entered chan struct{}
	release chan struct{}
	err     error
	once    sync.Once
}

func (w *pendingResponseGateWriter) Write(chunk []byte) (int, error) {
	w.once.Do(func() {
		close(w.entered)
		<-w.release
	})
	if w.err != nil {
		return 0, w.err
	}
	return w.ResponseRecorder.Write(chunk)
}

func TestPendingResponseCleanEndDrainsPastWriteDelay(t *testing.T) {
	t.Parallel()
	pending := newPendingRequest()
	budget := &byteBudget{limit: 4096}
	pending.globalBudget = budget
	defer pending.discardBody()
	for _, chunk := range []string{"first", "second"} {
		if err := pending.sendBody([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	pending.finish()
	w := &pendingResponseGateWriter{
		ResponseRecorder: httptest.NewRecorder(),
		entered:          make(chan struct{}), release: make(chan struct{}),
	}
	var once sync.Once
	unblock := func() { once.Do(func() { close(w.release) }) }
	defer unblock()
	finished := make(chan bool, 1)
	const timeout = 20 * time.Millisecond
	go func() {
		finished <- (&Server{}).writeStreamedResponseBody(w,
			httptest.NewRequest(http.MethodGet, "/", nil), pending, timeout)
	}()
	select {
	case <-w.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("response writer did not receive the first chunk")
	}
	<-time.After(2 * timeout)
	unblock()
	select {
	case complete := <-finished:
		if !complete || w.Body.String() != "firstsecond" {
			t.Fatalf("buffered response truncated after slow write: complete=%v body=%q", complete, w.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("clean response did not finish")
	}
	if budget.used.Load() != 0 {
		t.Fatal("clean response retained budget")
	}
}

func TestPendingResponseAbortReleasesOnlyQueuedChunks(t *testing.T) {
	for _, writeError := range []bool{false, true} {
		t.Run(fmt.Sprintf("writeError=%v", writeError), func(t *testing.T) {
			pending := newPendingRequest()
			global, session := &byteBudget{limit: 3 * 4096}, &byteBudget{limit: 3 * 4096}
			pending.globalBudget, pending.sessionBudget = global, session
			defer pending.discardBody()
			for range 3 {
				chunk := append(make([]byte, 0, 4096), "event"...)
				if err := pending.sendBody(chunk); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			w := &pendingResponseGateWriter{
				ResponseRecorder: httptest.NewRecorder(),
				entered:          make(chan struct{}), release: make(chan struct{}),
			}
			if writeError {
				w.err = errors.New("visitor disconnected")
			}
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(w.release) }) }
			defer unblock()
			finished := make(chan bool, 1)
			go func() {
				finished <- (&Server{}).writeStreamedResponseBody(w,
					httptest.NewRequestWithContext(ctx, http.MethodGet, "/", nil), pending, time.Second)
			}()
			select {
			case <-w.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("response writer did not receive a chunk")
			}
			pending.abort()
			pending.discardBody()
			if global.used.Load() != 4096 || session.used.Load() != 4096 {
				t.Fatalf("discard released an in-flight chunk: global=%d session=%d", global.used.Load(), session.used.Load())
			}
			cancel()
			unblock()
			select {
			case complete := <-finished:
				if complete {
					t.Fatal("aborted response reported successful completion")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("aborted response writer did not stop")
			}
			if global.used.Load() != 0 || session.used.Load() != 0 {
				t.Fatal("completed write retained the in-flight reservation")
			}
		})
	}
}
