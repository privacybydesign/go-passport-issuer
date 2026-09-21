package main

import (
	"context"
	"sync"
	"time"
)

// memoryStore is the Store for local development and tests: one process,
// nothing survives a restart. Expiry is checked on access and swept on
// every Create, which is enough at these volumes.
type memoryStore struct {
	now   func() time.Time
	mu    sync.Mutex
	items map[string]memoryItem
}

type memoryItem struct {
	s    Session
	dies time.Time
}

func newMemoryStore(now func() time.Time) *memoryStore {
	return &memoryStore{now: now, items: map[string]memoryItem{}}
}

func (m *memoryStore) Create(_ context.Context, s Session, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for id, it := range m.items {
		if !it.dies.After(now) {
			delete(m.items, id)
		}
	}
	m.items[s.ID] = memoryItem{s: s, dies: now.Add(ttl)}
	return nil
}

// live returns the item if it exists and has not expired; callers hold mu.
func (m *memoryStore) live(id string) (memoryItem, bool) {
	it, ok := m.items[id]
	if !ok || !it.dies.After(m.now()) {
		return memoryItem{}, false
	}
	return it, true
}

func (m *memoryStore) Get(_ context.Context, id string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.live(id)
	if !ok {
		return Session{}, ErrNotFound
	}
	return it.s, nil
}

func (m *memoryStore) Claim(_ context.Context, id string, startedAt time.Time, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.live(id)
	if !ok {
		return ErrNotFound
	}
	if it.s.Status != StatusPending {
		return ErrNotPending
	}
	it.s.Status = StatusStreaming
	it.s.StartedAt = startedAt
	it.dies = m.now().Add(ttl)
	m.items[id] = it
	return nil
}

func (m *memoryStore) Finish(_ context.Context, s Session, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.live(s.ID)
	if !ok {
		return ErrNotFound
	}
	it.s.Status = s.Status
	it.s.EndedAt = s.EndedAt
	it.s.Frames = s.Frames
	it.s.Distance = s.Distance
	it.s.Passed = s.Passed
	it.dies = m.now().Add(ttl)
	m.items[s.ID] = it
	return nil
}

func (m *memoryStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, id)
	return nil
}

func (m *memoryStore) Ping(context.Context) error { return nil }
