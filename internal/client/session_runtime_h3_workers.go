package client

import "sync"

type h3WorkerManager struct {
	mu         sync.Mutex
	opening    int
	active     int
	maxWorkers int
	openFn     func()
}

func newH3WorkerManager(maxWorkers int, openFn func()) *h3WorkerManager {
	if maxWorkers <= 0 {
		maxWorkers = 1
	}
	return &h3WorkerManager{
		maxWorkers: maxWorkers,
		openFn:     openFn,
	}
}

func (m *h3WorkerManager) request(desired int) {
	if m == nil {
		return
	}
	if desired <= 0 {
		desired = 1
	}
	for {
		m.mu.Lock()
		if m.active+m.opening >= m.maxWorkers || desired <= 0 {
			m.mu.Unlock()
			return
		}
		m.opening++
		m.mu.Unlock()
		desired--
		go m.openFn()
	}
}

func (m *h3WorkerManager) opened() {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.opening > 0 {
		m.opening--
	}
	m.active++
	m.mu.Unlock()
}

func (m *h3WorkerManager) closed() {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.active > 0 {
		m.active--
	}
	m.mu.Unlock()
}
