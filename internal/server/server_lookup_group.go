package server

import (
	"context"
	"sync"
)

type lookupCall[T any] struct {
	done  chan struct{}
	value T
	err   error
}

type lookupGroup[T any] struct {
	mu    sync.Mutex
	calls map[string]*lookupCall[T]
}

func (g *lookupGroup[T]) do(ctx context.Context, key string, lookup func() (T, error)) (T, error) {
	g.mu.Lock()
	if g.calls == nil {
		g.calls = make(map[string]*lookupCall[T])
	}
	if call := g.calls[key]; call != nil {
		g.mu.Unlock()
		select {
		case <-ctx.Done():
			var zero T
			return zero, ctx.Err()
		case <-call.done:
			return call.value, call.err
		}
	}

	call := &lookupCall[T]{done: make(chan struct{})}
	g.calls[key] = call
	g.mu.Unlock()

	go func() {
		call.value, call.err = lookup()
		close(call.done)
		g.mu.Lock()
		delete(g.calls, key)
		g.mu.Unlock()
	}()
	select {
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	case <-call.done:
		return call.value, call.err
	}
}
