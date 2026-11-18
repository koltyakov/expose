package server

import (
	"bytes"
	"sync"
	"testing"

	"github.com/koltyakov/expose/internal/tunnelproto"
)

// A shared tunnel must be able to buffer one small event on each of 128
// streams without exhausting the default 16 MiB response budget.
func TestSmallStreamEventsShareResponseBudget(t *testing.T) {
	var frame bytes.Buffer
	if err := tunnelproto.WriteStreamBinaryFrameV2(&frame, tunnelproto.BinaryFrameRespBody, "id", 0, []byte("data: 1\n\n")); err != nil {
		t.Fatal(err)
	}
	budget := &byteBudget{limit: 16 << 20}
	for range 128 {
		var msg tunnelproto.Message
		if err := tunnelproto.ReadStreamMessageV2(bytes.NewReader(frame.Bytes()), 1024, &msg); err != nil {
			t.Fatal(err)
		}
		p := newPendingRequest()
		p.sessionBudget = budget
		defer p.discardBody()
		if err := p.sendBody(msg.BodyChunk.Data); err != nil {
			t.Fatal("small event rejected by the tunnel byte budget")
		}
	}
}

func TestPendingResponseBudgetsCountCapacityAndRollback(t *testing.T) {
	t.Parallel()
	global := &byteBudget{limit: 192}
	sessionA := &byteBudget{limit: 128}
	sessionB := &byteBudget{limit: 128}
	first, second := newPendingRequest(), newPendingRequest()
	first.sessionBudget, first.globalBudget = sessionA, global
	second.sessionBudget, second.globalBudget = sessionB, global
	defer first.discardBody()
	defer second.discardBody()
	chunk := make([]byte, 1, 128)
	if err := first.sendBody(chunk); err != nil {
		t.Fatal("first chunk should fit")
	}
	if global.used.Load() != 128 || sessionA.used.Load() != 128 {
		t.Fatal("budget counted payload length rather than retained capacity")
	}
	if err := first.sendBody([]byte("x")); err != errResponseQueueBudgetExceeded {
		t.Fatal("per-tunnel budget exceeded")
	}
	if err := second.sendBody(chunk); err != errResponseQueueBudgetExceeded {
		t.Fatal("global budget exceeded")
	}
	if sessionB.used.Load() != 0 || global.used.Load() != 128 {
		t.Fatal("failed global admission retained a reservation")
	}
	first.abort()
	first.discardBody()
	if err := second.sendBody(chunk); err != nil {
		t.Fatal("aborted request did not release its budget")
	}
	body, _ := second.nextBodyChunk()
	second.releaseBodyChunk(body)
	if global.used.Load() != 0 || sessionA.used.Load() != 0 || sessionB.used.Load() != 0 {
		t.Fatal("consumed response retained a reservation")
	}
	if err := first.sendBody(chunk); err != errResponseClosed {
		t.Fatal("closed request accepted another chunk")
	}
}

func TestPendingResponseTinyChunksReserveQueueStorage(t *testing.T) {
	t.Parallel()
	budget := &byteBudget{limit: 128}
	p := newPendingRequest()
	p.globalBudget = budget
	defer p.discardBody()
	for range 2 {
		if err := p.sendBody([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.sendBody([]byte("x")); err != errResponseQueueBudgetExceeded {
		t.Fatal("tiny chunks evaded the queue byte budget")
	}
	if budget.used.Load() != 128 {
		t.Fatalf("tiny chunk reservations = %d, want 128", budget.used.Load())
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
