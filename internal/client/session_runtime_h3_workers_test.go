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
