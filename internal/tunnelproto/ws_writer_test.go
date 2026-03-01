package tunnelproto

import (
	"sync"
	"testing"
)

func TestWSWritePumpPrioritizesControlWrites(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})

	var mu sync.Mutex
	order := make([]string, 0, 3)

	pump := newWSWritePumpWithWriter(func(req wsWriteRequest) error {
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
	}, 4, 4)
	defer pump.Close()

	errCh := make(chan error, 3)
	go func() {
		errCh <- pump.WriteBinaryFrame(BinaryFrameRespBody, "low-1", 0, []byte("a"))
	}()

	<-started

	lowReq := wsWriteRequest{
		frameKind: BinaryFrameRespBody,
		id:        "low-2",
		payload:   []byte("b"),
		binary:    true,
		done:      make(chan error, 1),
	}
	highReq := wsWriteRequest{
		msg:  Message{Kind: KindPing},
		done: make(chan error, 1),
	}
	pump.low <- lowReq
	pump.high <- highReq

	go func() { errCh <- <-lowReq.done }()
	go func() { errCh <- <-highReq.done }()

	close(release)

	for range 3 {
		if err := <-errCh; err != nil {
			t.Fatalf("unexpected write error: %v", err)
		}
	}

	mu.Lock()
	got := append([]string(nil), order...)
	mu.Unlock()

	want := []string{"low-1", KindPing, "low-2"}
	if len(got) != len(want) {
		t.Fatalf("unexpected write order length: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected write order: got %v want %v", got, want)
		}
	}
}

func TestWSWritePumpCloseRejectsNewWrites(t *testing.T) {
	t.Parallel()

	pump := newWSWritePumpWithWriter(func(req wsWriteRequest) error { return nil }, 1, 1)
	pump.Close()

	if err := pump.WriteJSON(Message{Kind: KindPing}); err != ErrWSWritePumpClosed {
		t.Fatalf("expected ErrWSWritePumpClosed, got %v", err)
	}
}
