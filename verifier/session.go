package main

import (
	"context"
	"errors"
	"time"
)

// Status is a session's state as reported to the issuer.
type Status string

const (
	StatusPending   Status = "pending"
	StatusStreaming Status = "streaming"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusExpired   Status = "expired"
)

// Session is one face verification session. It never holds the portrait or
// a frame; those live in the parent's memory and then in the worker.
type Session struct {
	ID     string
	Status Status
	// TokenHash is SHA-256 of the bearer token handed to the issuer. The
	// token itself is stored nowhere.
	TokenHash      []byte
	PortraitSHA256 string
	DocumentType   string
	CreatedAt      time.Time
	// ExpiresAt is the pending deadline: a stream must start before it.
	ExpiresAt time.Time
	StartedAt time.Time
	EndedAt   time.Time
	Frames    int
	// Distance and Passed are set only when the engine completed; Passed is
	// the threshold decision on Distance.
	Distance *float64
	Passed   *bool
}

// StatusAt is the status the issuer should see at now: a pending session past
// its deadline reads as expired even while its record still exists.
func (s Session) StatusAt(now time.Time) Status {
	if s.Status == StatusPending && !now.Before(s.ExpiresAt) {
		return StatusExpired
	}
	return s.Status
}

// DurationMs is the streaming time once the session has ended, else 0.
func (s Session) DurationMs() int64 {
	if s.StartedAt.IsZero() || s.EndedAt.IsZero() {
		return 0
	}
	return s.EndedAt.Sub(s.StartedAt).Milliseconds()
}

var (
	ErrNotFound   = errors.New("session not found")
	ErrNotPending = errors.New("session is not pending")
)

// Store keeps session records: in Redis in the cluster, so every replica and
// the issuer see the same state, and in memory for development and tests.
// Each write sets how long the record lives from that moment.
type Store interface {
	Create(ctx context.Context, s Session, ttl time.Duration) error
	Get(ctx context.Context, id string) (Session, error)
	// Claim moves a pending record to streaming. Of concurrent callers
	// exactly one succeeds; the others get ErrNotPending. It does not check
	// ExpiresAt; the caller does, against its own clock.
	Claim(ctx context.Context, id string, startedAt time.Time, ttl time.Duration) error
	// Finish writes the terminal fields of s: Status, EndedAt, Frames,
	// Distance and Passed.
	Finish(ctx context.Context, s Session, ttl time.Duration) error
	// Delete removes the record; an unknown id is not an error.
	Delete(ctx context.Context, id string) error
	// Ping reports whether the store is reachable, for readyz.
	Ping(ctx context.Context) error
}
