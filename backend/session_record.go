package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"go-passport-issuer/analytics"
)

// SessionRecord is what the token storage holds per document session. Before
// method assignment existed the stored value was the bare nonce; it is now a
// JSON record carrying the assigned method, so issuance can enforce it and
// the recordings can attribute every outcome to the method that was actually
// assigned.
type SessionRecord struct {
	Nonce string `json:"nonce"`
	// Method is empty when face verification is disabled for the environment
	// (and for sessions stored before methods existed, see loadSessionRecord).
	Method     FaceMethod `json:"method,omitempty"`
	AssignedAt time.Time  `json:"assigned_at,omitzero"`
	// Attempt is the wallet-reported attempt number within its document flow
	// (0 or 1 for a first attempt), kept for the recordings only.
	Attempt int `json:"attempt,omitempty"`
	// Client holds the wallet's coarse build labels for the recordings only.
	Client analytics.Client `json:"client,omitzero"`
}

// attemptKind labels the record's attempt for the recordings.
func (r SessionRecord) attemptKind() analytics.AttemptKind {
	if r.Attempt > 1 {
		return analytics.AttemptRetry
	}
	return analytics.AttemptFirst
}

func storeSessionRecord(storage TokenStorage, sessionId string, rec SessionRecord) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("failed to marshal session record: %w", err)
	}
	return storage.StoreToken(sessionId, string(b))
}

// loadSessionRecord reads a session. A value that is not a JSON object is a
// bare nonce written by an issuer before this record existed (or by one still
// running beside this version during a rollout) and is read as a Regula-era
// session without an assignment.
func loadSessionRecord(storage TokenStorage, sessionId string) (SessionRecord, error) {
	raw, err := storage.RetrieveToken(sessionId)
	if err != nil {
		return SessionRecord{}, err
	}
	if !strings.HasPrefix(strings.TrimSpace(raw), "{") {
		return SessionRecord{Nonce: raw}, nil
	}
	var rec SessionRecord
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		return SessionRecord{}, fmt.Errorf("failed to unmarshal session record: %w", err)
	}
	return rec, nil
}

// validateSession checks that the session exists and the nonce matches, and
// returns the session's record so the caller knows its method assignment.
func validateSession(storage TokenStorage, sessionId, nonce string) (SessionRecord, error) {
	slog.Debug("Validating session and nonce", "session_id", sessionId)
	rec, err := loadSessionRecord(storage, sessionId)
	if err != nil {
		slog.Warn("Failed to retrieve token from storage", "session_id", sessionId, "error", err)
		return SessionRecord{}, fmt.Errorf("%s: %w", ERR_TOKEN_RETRIEVAL, err)
	}

	if rec.Nonce == "" || rec.Nonce != nonce {
		slog.Warn("Invalid nonce or session", "session_id", sessionId, "nonce_empty", rec.Nonce == "", "nonce_match", rec.Nonce == nonce)
		return SessionRecord{}, fmt.Errorf("%s", ERR_INVALID_NONCE_SESSION)
	}

	slog.Debug("Session validation successful", "session_id", sessionId)
	return rec, nil
}
