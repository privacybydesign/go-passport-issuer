package main

import (
	"sync"
	"time"
)

// portraitBox holds each pending session's portrait in this process's memory
// until its stream starts. The portrait is biometric data: it goes from the
// issuer's request to here, then to the worker, and nowhere else, never into
// Redis or a log.
//
// The consequence is that a stream must reach the replica that created its
// session. That holds with the single replica of the initial deployment;
// more replicas need sticky routing or a shared, encrypted portrait store.
type portraitBox struct {
	now   func() time.Time
	mu    sync.Mutex
	items map[string]portraitItem
}

type portraitItem struct {
	portrait string
	dies     time.Time
}

func newPortraitBox(now func() time.Time) *portraitBox {
	return &portraitBox{now: now, items: map[string]portraitItem{}}
}

func (b *portraitBox) Put(id, portrait string, ttl time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	for k, it := range b.items {
		if !it.dies.After(now) {
			delete(b.items, k)
		}
	}
	b.items[id] = portraitItem{portrait: portrait, dies: now.Add(ttl)}
}

func (b *portraitBox) Get(id string) (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	it, ok := b.items[id]
	if !ok || !it.dies.After(b.now()) {
		return "", false
	}
	return it.portrait, true
}

func (b *portraitBox) Delete(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.items, id)
}
