package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisStore keeps one hash per session under prefix. The cluster's ACL user
// may only touch keys under "<username>:", so prefix is "<username>:iris:".
//
// Claim is made atomic with SET NX on a side key rather than a Lua script or
// WATCH, because plain string commands are the only ones certain to be
// permitted for the ACL user.
type redisStore struct {
	rdb    *redis.Client
	prefix string
}

func newRedisStore(rdb *redis.Client, prefix string) *redisStore {
	return &redisStore{rdb: rdb, prefix: prefix}
}

func (r *redisStore) key(id string) string      { return r.prefix + "session:" + id }
func (r *redisStore) claimKey(id string) string { return r.prefix + "claim:" + id }

func (r *redisStore) Create(ctx context.Context, s Session, ttl time.Duration) error {
	_, err := r.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.HSet(ctx, r.key(s.ID), sessionToFields(s))
		p.PExpire(ctx, r.key(s.ID), ttl)
		return nil
	})
	if err != nil {
		return fmt.Errorf("redis create session: %w", err)
	}
	return nil
}

func (r *redisStore) Get(ctx context.Context, id string) (Session, error) {
	fields, err := r.rdb.HGetAll(ctx, r.key(id)).Result()
	if err != nil {
		return Session{}, fmt.Errorf("redis get session: %w", err)
	}
	if len(fields) == 0 {
		return Session{}, ErrNotFound
	}
	return fieldsToSession(id, fields)
}

func (r *redisStore) Claim(ctx context.Context, id string, startedAt time.Time, ttl time.Duration) error {
	won, err := r.rdb.SetNX(ctx, r.claimKey(id), startedAt.UTC().Format(time.RFC3339Nano), ttl).Result()
	if err != nil {
		return fmt.Errorf("redis claim session: %w", err)
	}
	if !won {
		return ErrNotPending
	}
	exists, err := r.rdb.Exists(ctx, r.key(id)).Result()
	if err != nil {
		return fmt.Errorf("redis claim session: %w", err)
	}
	if exists == 0 {
		_ = r.rdb.Del(ctx, r.claimKey(id)).Err()
		return ErrNotFound
	}
	_, err = r.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.HSet(ctx, r.key(id), "status", string(StatusStreaming), "started_at", formatTime(startedAt))
		p.PExpire(ctx, r.key(id), ttl)
		return nil
	})
	if err != nil {
		return fmt.Errorf("redis claim session: %w", err)
	}
	return nil
}

func (r *redisStore) Finish(ctx context.Context, s Session, ttl time.Duration) error {
	_, err := r.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.HSet(ctx, r.key(s.ID), terminalFields(s))
		p.PExpire(ctx, r.key(s.ID), ttl)
		p.PExpire(ctx, r.claimKey(s.ID), ttl)
		return nil
	})
	if err != nil {
		return fmt.Errorf("redis finish session: %w", err)
	}
	return nil
}

func (r *redisStore) Delete(ctx context.Context, id string) error {
	if err := r.rdb.Del(ctx, r.key(id), r.claimKey(id)).Err(); err != nil {
		return fmt.Errorf("redis delete session: %w", err)
	}
	return nil
}

func (r *redisStore) Ping(ctx context.Context) error {
	return r.rdb.Ping(ctx).Err()
}

// Hash field encoding. Times are RFC 3339 with nanoseconds in UTC; absent
// optional values are absent fields.

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, s)
}

func sessionToFields(s Session) map[string]any {
	f := map[string]any{
		"status":          string(s.Status),
		"token_hash":      hex.EncodeToString(s.TokenHash),
		"portrait_sha256": s.PortraitSHA256,
		"document_type":   s.DocumentType,
		"created_at":      formatTime(s.CreatedAt),
		"expires_at":      formatTime(s.ExpiresAt),
		"started_at":      formatTime(s.StartedAt),
	}
	for k, v := range terminalFields(s) {
		f[k] = v
	}
	return f
}

func terminalFields(s Session) map[string]any {
	f := map[string]any{
		"status":   string(s.Status),
		"ended_at": formatTime(s.EndedAt),
		"frames":   strconv.Itoa(s.Frames),
	}
	if s.Distance != nil {
		f["distance"] = strconv.FormatFloat(*s.Distance, 'g', -1, 64)
	}
	if s.Passed != nil {
		f["passed"] = strconv.FormatBool(*s.Passed)
	}
	return f
}

func fieldsToSession(id string, f map[string]string) (Session, error) {
	s := Session{
		ID:             id,
		Status:         Status(f["status"]),
		PortraitSHA256: f["portrait_sha256"],
		DocumentType:   f["document_type"],
	}
	var err error
	if s.TokenHash, err = hex.DecodeString(f["token_hash"]); err != nil {
		return Session{}, fmt.Errorf("session %s: token_hash: %w", id, err)
	}
	times := map[string]*time.Time{
		"created_at": &s.CreatedAt, "expires_at": &s.ExpiresAt,
		"started_at": &s.StartedAt, "ended_at": &s.EndedAt,
	}
	for name, dst := range times {
		if *dst, err = parseTime(f[name]); err != nil {
			return Session{}, fmt.Errorf("session %s: %s: %w", id, name, err)
		}
	}
	if v := f["frames"]; v != "" {
		if s.Frames, err = strconv.Atoi(v); err != nil {
			return Session{}, fmt.Errorf("session %s: frames: %w", id, err)
		}
	}
	if v, ok := f["distance"]; ok {
		d, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return Session{}, fmt.Errorf("session %s: distance: %w", id, err)
		}
		s.Distance = &d
	}
	if v, ok := f["passed"]; ok {
		p, err := strconv.ParseBool(v)
		if err != nil {
			return Session{}, fmt.Errorf("session %s: passed: %w", id, err)
		}
		s.Passed = &p
	}
	return s, nil
}
