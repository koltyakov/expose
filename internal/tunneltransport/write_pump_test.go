package tunneltransport

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/tunnelproto"
)

func TestWritePumpPrioritizesControlWrites(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})

	var mu sync.Mutex
	order := make([]string, 0, 3)

	pump := NewWritePump(func(req writeRequest) error {
		label := req.msg.Kind
		if req.binary {
			label = req.id
		}
		if label == "low-1" {
			close(started)
			<-release
		}

		mu.Lock()
		order = append(order, label)
		mu.Unlock()
		return nil
	}, nil, 4, 4, time.Second, time.Second)
	defer pump.Close()

	errCh := make(chan error, 3)
	go func() {
		errCh <- pump.WriteBinaryFrame(tunnelproto.BinaryFrameRespBody, "low-1", 0, []byte("a"))
	}()

	<-started

	lowReq := writeRequest{
		frameKind: tunnelproto.BinaryFrameRespBody,
		id:        "low-2",
		payload:   []byte("b"),
		binary:    true,
		done:      acquireWriteCompletion(),
	}
	highReq := writeRequest{
		msg:  tunnelproto.Message{Kind: tunnelproto.KindPing},
		done: acquireWriteCompletion(),
	}
	pump.low <- lowReq
	pump.high <- highReq

	go func() {
		err := <-lowReq.done.ch
		releaseWriteCompletion(lowReq.done)
		errCh <- err
	}()
	go func() {
		err := <-highReq.done.ch
		releaseWriteCompletion(highReq.done)
		errCh <- err
	}()

	close(release)

	for range 3 {
		if err := <-errCh; err != nil {
			t.Fatalf("unexpected write error: %v", err)
		}
	}

	mu.Lock()
	got := append([]string(nil), order...)
	mu.Unlock()

	want := []string{"low-1", tunnelproto.KindPing, "low-2"}
	if len(got) != len(want) {
		t.Fatalf("unexpected write order length: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected write order: got %v want %v", got, want)
		}
	}
}

func TestWritePumpCloseRejectsNewWrites(t *testing.T) {
	t.Parallel()

	pump := NewWritePump(func(writeRequest) error { return nil }, nil, 1, 1, time.Second, time.Second)
	pump.Close()

	if err := pump.WriteJSON(tunnelproto.Message{Kind: tunnelproto.KindPing}); err != ErrWritePumpClosed {
		t.Fatalf("expected ErrWritePumpClosed, got %v", err)
	}
}

func TestWritePumpDefaultCapacityAndTimeouts(t *testing.T) {
	t.Parallel()

	// Passing zero/negative values for cap and timeouts should use defaults.
	var written int
	pump := NewWritePump(func(writeRequest) error {
		written++
		return nil
	}, nil, 0, 0, 0, 0)
	defer pump.Close()

	if err := pump.WriteJSON(tunnelproto.Message{Kind: tunnelproto.KindPing}); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	if written != 1 {
		t.Fatalf("expected 1 write, got %d", written)
	}
}

func TestWritePumpWriteError(t *testing.T) {
	t.Parallel()

	writeErr := errors.New("write failed")
	pump := NewWritePump(func(writeRequest) error {
		return writeErr
	}, nil, 4, 4, time.Second, time.Second)

	err := pump.WriteJSON(tunnelproto.Message{Kind: tunnelproto.KindPing})
	if !errors.Is(err, writeErr) {
		t.Fatalf("expected writeErr, got %v", err)
	}

	// After a write error the pump should be closed.
	<-pump.done
	if err := pump.WriteJSON(tunnelproto.Message{Kind: tunnelproto.KindPing}); !errors.Is(err, ErrWritePumpClosed) {
		t.Fatalf("expected ErrWritePumpClosed after write error, got %v", err)
	}
}

func TestWritePumpNilWriteFn(t *testing.T) {
	t.Parallel()

	pump := NewWritePump(nil, nil, 1, 1, time.Second, time.Second)

	err := pump.WriteJSON(tunnelproto.Message{Kind: tunnelproto.KindPing})
	if !errors.Is(err, ErrWritePumpClosed) {
		t.Fatalf("expected ErrWritePumpClosed with nil writeFn, got %v", err)
	}

	<-pump.done
}

func TestWritePumpEnqueueAfterStop(t *testing.T) {
	t.Parallel()

	// Create a pump, close it, then try to enqueue via both high and low paths.
	pump := NewWritePump(func(writeRequest) error {
		return nil
	}, nil, 4, 4, time.Second, time.Second)
	pump.Close()

	if err := pump.WriteBinaryFrame(tunnelproto.BinaryFrameRespBody, "test", 0, []byte("x")); !errors.Is(err, ErrWritePumpClosed) {
		t.Fatalf("expected ErrWritePumpClosed for binary write after close, got %v", err)
	}
}

func TestWritePumpConcurrentWrites(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var count int

	pump := NewWritePump(func(writeRequest) error {
		mu.Lock()
		count++
		mu.Unlock()
		return nil
	}, nil, 8, 8, time.Second, time.Second)
	defer pump.Close()

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				_ = pump.WriteJSON(tunnelproto.Message{Kind: tunnelproto.KindPing})
			} else {
				_ = pump.WriteBinaryFrame(tunnelproto.BinaryFrameRespBody, "c", 0, []byte("x"))
			}
		}(i)
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if count != n {
		t.Fatalf("expected %d writes, got %d", n, count)
	}
}

func TestReleaseWriteCompletionNil(t *testing.T) {
	t.Parallel()
	// Should not panic.
	releaseWriteCompletion(nil)
}

func TestAcquireReleaseWriteCompletion(t *testing.T) {
	t.Parallel()

	comp := acquireWriteCompletion()
	if comp == nil {
		t.Fatal("expected non-nil completion")
	}
	// Simulate a pending error in the channel.
	comp.ch <- errors.New("leftover")
	releaseWriteCompletion(comp)

	// Acquire again — channel should be drained.
	comp2 := acquireWriteCompletion()
	select {
	case <-comp2.ch:
		t.Fatal("channel should be empty after acquire")
	default:
	}
	releaseWriteCompletion(comp2)
}

func TestWritePumpBackpressureClosesPump(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	closeCalled := make(chan struct{}, 1)

	pump := NewWritePump(func(req writeRequest) error {
		if req.id == "in-flight" {
			close(started)
			<-release
		}
		return nil
	}, func() {
		select {
		case closeCalled <- struct{}{}:
		default:
		}
	}, 1, 1, time.Second, 10*time.Millisecond)

	errCh := make(chan error, 2)
	go func() {
		errCh <- pump.WriteBinaryFrame(tunnelproto.BinaryFrameRespBody, "in-flight", 0, []byte("a"))
	}()

	<-started

	go func() {
		errCh <- pump.WriteBinaryFrame(tunnelproto.BinaryFrameRespBody, "queued", 0, []byte("b"))
	}()

	time.Sleep(5 * time.Millisecond)

	if err := pump.WriteBinaryFrame(tunnelproto.BinaryFrameRespBody, "overflow", 0, []byte("c")); !errors.Is(err, ErrWritePumpBackpressure) {
		t.Fatalf("expected ErrWritePumpBackpressure, got %v", err)
	}

	select {
	case <-closeCalled:
	case <-time.After(time.Second):
		t.Fatal("expected close callback to be invoked on backpressure")
	}

	close(release)

	var sawClosed bool
	for range 2 {
		err := <-errCh
		if errors.Is(err, ErrWritePumpClosed) {
			sawClosed = true
		}
	}
	if !sawClosed {
		t.Fatal("expected queued writes to fail after backpressure closes the pump")
	}

	if err := pump.WriteJSON(tunnelproto.Message{Kind: tunnelproto.KindPing}); !errors.Is(err, ErrWritePumpClosed) {
		t.Fatalf("expected closed pump after backpressure, got %v", err)
	}
}

// TestWriteJSONAsyncDoesNotWaitForWrite is the regression test for the read
// loop stall: WriteJSON blocks until the pump finishes writing, so a slow peer
// mid-frame would freeze the caller. WriteJSONAsync must return immediately.
func TestWriteJSONAsyncDoesNotWaitForWrite(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	writing := make(chan struct{})
	var once sync.Once

	pump := NewWritePump(func(req writeRequest) error {
		once.Do(func() { close(writing) })
		<-release
		return nil
	}, nil, 8, 8, time.Second, time.Second)
	defer func() {
		close(release)
		pump.Close()
	}()

	// Occupy the writer so nothing can drain.
	go func() { _ = pump.WriteJSON(tunnelproto.Message{Kind: tunnelproto.KindPing}) }()
	<-writing

	done := make(chan error, 1)
	go func() { done <- pump.WriteJSONAsync(tunnelproto.Message{Kind: tunnelproto.KindPong}) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WriteJSONAsync() error = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("WriteJSONAsync blocked waiting for the in-flight write")
	}
}

// TestWriteJSONAsyncReportsBackpressureWithoutClosing checks that a saturated
// control lane costs one dropped frame rather than tearing down the tunnel.
func TestWriteJSONAsyncReportsBackpressureWithoutClosing(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	writing := make(chan struct{})
	var once sync.Once

	pump := NewWritePump(func(req writeRequest) error {
		once.Do(func() { close(writing) })
		<-release
		return nil
	}, nil, 1, 1, time.Second, time.Second)
	defer func() {
		close(release)
		pump.Close()
	}()

	go func() { _ = pump.WriteJSON(tunnelproto.Message{Kind: tunnelproto.KindPing}) }()
	<-writing

	// Fill the single control slot, then overflow it.
	var lastErr error
	for range 4 {
		lastErr = pump.WriteJSONAsync(tunnelproto.Message{Kind: tunnelproto.KindPong})
	}
	if !errors.Is(lastErr, ErrWritePumpBackpressure) {
		t.Fatalf("expected backpressure error, got %v", lastErr)
	}
	if pump.closed.Load() {
		t.Fatal("a full control lane must not close the pump")
	}
}

// TestWritePumpDoesNotStarveDataLane covers sustained control traffic: strict
// priority for the control lane would let it starve data frames forever.
func TestWritePumpDoesNotStarveDataLane(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	dataWrites := 0

	// Each write takes long enough that producers always have something
	// queued when the pump picks the next message, which is the condition
	// under which strict control-lane priority starves data.
	pump := NewWritePump(func(req writeRequest) error {
		if req.binary {
			mu.Lock()
			dataWrites++
			mu.Unlock()
		}
		time.Sleep(200 * time.Microsecond)
		return nil
	}, nil, 64, 64, time.Second, time.Second)
	defer pump.Close()

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Keep the control lane permanently non-empty. These must be async
	// writes: WriteJSON waits for its own write to complete, which would let
	// the lane drain between messages and hide the starvation.
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					_ = pump.WriteJSONAsync(tunnelproto.Message{Kind: tunnelproto.KindPing})
				}
			}
		})
	}

	// Let the control producers get ahead of the pump.
	time.Sleep(20 * time.Millisecond)

	// A single data frame must still get through.
	sent := make(chan error, 1)
	wg.Go(func() {
		sent <- pump.WriteBinaryFrame(tunnelproto.BinaryFrameRespBody, "d-1", 0, []byte("x"))
	})

	select {
	case err := <-sent:
		if err != nil {
			t.Errorf("data write failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("data frame starved by continuous control traffic")
	}

	close(stop)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if dataWrites == 0 {
		t.Error("no data frames were written")
	}
}
