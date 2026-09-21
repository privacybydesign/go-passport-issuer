package main

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func sampleSession(now time.Time) Session {
	return Session{
		ID:             "fs_0123",
		Status:         StatusPending,
		TokenHash:      []byte{1, 2, 3, 4},
		PortraitSHA256: "abcd",
		DocumentType:   "passport",
		CreatedAt:      now,
		ExpiresAt:      now.Add(10 * time.Minute),
	}
}

// storeContract is what every Store must do; the memory store runs it always,
// the Redis store when IRIS_TEST_REDIS_ADDR points at a server.
func storeContract(t *testing.T, store Store, clock *fakeClock) {
	ctx := context.Background()
	now := clock.Now()
	s := sampleSession(now)
	require.NoError(t, store.Create(ctx, s, time.Hour))

	got, err := store.Get(ctx, s.ID)
	require.NoError(t, err)
	require.Equal(t, StatusPending, got.Status)
	require.Equal(t, s.TokenHash, got.TokenHash)
	require.Equal(t, "abcd", got.PortraitSHA256)
	require.Equal(t, "passport", got.DocumentType)
	require.True(t, s.ExpiresAt.Equal(got.ExpiresAt))
	require.Nil(t, got.Passed)
	require.Nil(t, got.Distance)

	_, err = store.Get(ctx, "fs_unknown")
	require.ErrorIs(t, err, ErrNotFound)

	// Exactly one claim wins.
	started := now.Add(time.Second)
	require.NoError(t, store.Claim(ctx, s.ID, started, time.Hour))
	require.ErrorIs(t, store.Claim(ctx, s.ID, started, time.Hour), ErrNotPending)
	require.ErrorIs(t, store.Claim(ctx, "fs_unknown", started, time.Hour), ErrNotFound)
	got, err = store.Get(ctx, s.ID)
	require.NoError(t, err)
	require.Equal(t, StatusStreaming, got.Status)
	require.True(t, started.Equal(got.StartedAt))

	// Finish writes the terminal fields and nothing else.
	distance, passed := 0.41, true
	fin := got
	fin.Status = StatusCompleted
	fin.EndedAt = started.Add(4 * time.Second)
	fin.Frames = 60
	fin.Distance = &distance
	fin.Passed = &passed
	fin.PortraitSHA256 = "must not change"
	require.NoError(t, store.Finish(ctx, fin, time.Hour))
	got, err = store.Get(ctx, s.ID)
	require.NoError(t, err)
	require.Equal(t, StatusCompleted, got.Status)
	require.Equal(t, 60, got.Frames)
	require.Equal(t, 0.41, *got.Distance)
	require.True(t, *got.Passed)
	require.EqualValues(t, 4000, got.DurationMs())
	require.Equal(t, "abcd", got.PortraitSHA256)

	require.NoError(t, store.Delete(ctx, s.ID))
	require.NoError(t, store.Delete(ctx, s.ID), "deleting twice is fine")
	_, err = store.Get(ctx, s.ID)
	require.ErrorIs(t, err, ErrNotFound)

	require.NoError(t, store.Ping(ctx))
}

func TestMemoryStoreContract(t *testing.T) {
	clock := newFakeClock()
	storeContract(t, newMemoryStore(clock.Now), clock)
}

func TestMemoryStoreExpiry(t *testing.T) {
	clock := newFakeClock()
	store := newMemoryStore(clock.Now)
	ctx := context.Background()
	s := sampleSession(clock.Now())
	require.NoError(t, store.Create(ctx, s, time.Minute))

	clock.Advance(59 * time.Second)
	_, err := store.Get(ctx, s.ID)
	require.NoError(t, err)

	clock.Advance(2 * time.Second)
	_, err = store.Get(ctx, s.ID)
	require.ErrorIs(t, err, ErrNotFound)
	require.ErrorIs(t, store.Claim(ctx, s.ID, clock.Now(), time.Minute), ErrNotFound)
}

// Each write restarts the record's life from that moment.
func TestMemoryStoreTTLRestartsOnWrite(t *testing.T) {
	clock := newFakeClock()
	store := newMemoryStore(clock.Now)
	ctx := context.Background()
	s := sampleSession(clock.Now())
	require.NoError(t, store.Create(ctx, s, time.Minute))
	clock.Advance(50 * time.Second)
	require.NoError(t, store.Claim(ctx, s.ID, clock.Now(), time.Minute))
	clock.Advance(50 * time.Second)
	_, err := store.Get(ctx, s.ID)
	require.NoError(t, err, "claim gave it a fresh minute")
}

func TestSessionStatusAt(t *testing.T) {
	now := time.Now()
	s := sampleSession(now)
	require.Equal(t, StatusPending, s.StatusAt(now))
	require.Equal(t, StatusPending, s.StatusAt(s.ExpiresAt.Add(-time.Nanosecond)))
	require.Equal(t, StatusExpired, s.StatusAt(s.ExpiresAt))
	s.Status = StatusStreaming
	require.Equal(t, StatusStreaming, s.StatusAt(s.ExpiresAt.Add(time.Hour)), "only pending sessions expire")
}

func TestRedisFieldsRoundTrip(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 123456789, time.UTC)
	s := sampleSession(now)
	s.Status = StatusCompleted
	s.StartedAt = now.Add(time.Second)
	s.EndedAt = now.Add(5 * time.Second)
	s.Frames = 42
	d, p := 0.4142, true
	s.Distance, s.Passed = &d, &p

	fields := map[string]string{}
	for k, v := range sessionToFields(s) {
		fields[k] = fmt.Sprint(v)
	}
	got, err := fieldsToSession(s.ID, fields)
	require.NoError(t, err)
	require.Equal(t, s.Status, got.Status)
	require.Equal(t, s.TokenHash, got.TokenHash)
	require.Equal(t, s.PortraitSHA256, got.PortraitSHA256)
	require.Equal(t, s.DocumentType, got.DocumentType)
	for _, pair := range [][2]time.Time{
		{s.CreatedAt, got.CreatedAt}, {s.ExpiresAt, got.ExpiresAt}, {s.StartedAt, got.StartedAt}, {s.EndedAt, got.EndedAt},
	} {
		require.True(t, pair[0].Equal(pair[1]), "%v != %v", pair[0], pair[1])
	}
	require.Equal(t, 42, got.Frames)
	require.Equal(t, 0.4142, *got.Distance)
	require.True(t, *got.Passed)

	// A pending record has no terminal values, and none must be invented.
	pending, err := fieldsToSession("x", map[string]string{"status": "pending", "token_hash": "00", "frames": "0"})
	require.NoError(t, err)
	require.Nil(t, pending.Distance)
	require.Nil(t, pending.Passed)
	require.True(t, pending.StartedAt.IsZero())
}

func TestRedisStoreContract(t *testing.T) {
	addr := os.Getenv("IRIS_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("set IRIS_TEST_REDIS_ADDR (host:port of a scratch Redis) to run")
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	store := newRedisStore(rdb, "iris-verifier-test:iris:")
	clock := newFakeClock()
	t.Cleanup(func() { _ = store.Delete(context.Background(), sampleSession(clock.Now()).ID) })
	storeContract(t, store, clock)
}
