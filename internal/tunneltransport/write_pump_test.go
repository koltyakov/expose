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
