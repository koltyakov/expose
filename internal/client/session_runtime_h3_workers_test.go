package client

import "testing"

func TestH3WorkerManagerIgnoresNonPositiveRequests(t *testing.T) {
	t.Parallel()

	var opened int
	manager := newH3WorkerManager(4, func() {
		opened++
	})

	manager.request(0)
	manager.request(-2)

	if opened != 0 {
		t.Fatalf("expected no workers to open, got %d", opened)
	}
}

func TestH3WorkerManagerHonorsMaxWorkers(t *testing.T) {
	t.Parallel()

	var opened int
	manager := newH3WorkerManager(2, func() {
		opened++
	})

	manager.request(4)

	if opened != 2 {
		t.Fatalf("expected open count to clamp at 2, got %d", opened)
	}
}

func TestH3WorkerManagerCountsActiveWorkerAgainstMax(t *testing.T) {
	t.Parallel()

	var opened int
	manager := newH3WorkerManager(1, func() {
		opened++
	})

	manager.request(1)
	manager.opened()
	manager.request(1)

	if opened != 1 {
		t.Fatalf("expected active worker to reserve capacity, got %d opens", opened)
	}

	manager.closed()
	manager.request(1)
	if opened != 2 {
		t.Fatalf("expected a new worker after close, got %d opens", opened)
	}
}
