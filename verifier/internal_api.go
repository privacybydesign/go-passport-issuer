package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// The issuer's side of the verifier. These routes are served on
// the same listener as /stream, and only the ingress keeps them in-cluster.

// maxCreateBody bounds a create request; a chip portrait is tens of
// kilobytes, a large DG2 a few hundred.
const maxCreateBody = 8 << 20

type createSessionRequest struct {
	Portrait       string `json:"portrait"`
	PortraitSHA256 string `json:"portrait_sha256"`
	DocumentType   string `json:"document_type"`
}

type createSessionResponse struct {
	FaceSessionID string `json:"face_session_id"`
	Token         string `json:"token"`
	// ExpiresAt is RFC 3339 in UTC, whole seconds.
	ExpiresAt string `json:"expires_at"`
}

// sessionResponse is what the issuer's IrisSessionStatus decodes. Passed and
// Distance appear only once the engine completed.
type sessionResponse struct {
	Status         Status   `json:"status"`
	Passed         *bool    `json:"passed,omitempty"`
	Distance       *float64 `json:"distance,omitempty"`
	PortraitSHA256 string   `json:"portrait_sha256"`
	Frames         int      `json:"frames"`
	DurationMs     int64    `json:"duration_ms"`
}

var documentTypes = map[string]bool{"passport": true, "id_card": true, "driving_licence": true}

func (s *server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxCreateBody)
	var req createSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	portrait, err := decodeBase64(req.Portrait)
	if err != nil || len(portrait) == 0 {
		writeError(w, http.StatusBadRequest, "portrait is not base64")
		return
	}
	sum := sha256.Sum256(portrait)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), req.PortraitSHA256) {
		writeError(w, http.StatusBadRequest, "portrait_sha256 does not match the portrait")
		return
	}
	if !documentTypes[req.DocumentType] {
		writeError(w, http.StatusBadRequest, "document_type must be passport, id_card or driving_licence")
		return
	}

	id, token, tokenHash, err := newCredentials()
	if err != nil {
		s.log.Error("generate credentials", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	now := s.now()
	sess := Session{
		ID:             id,
		Status:         StatusPending,
		TokenHash:      tokenHash,
		PortraitSHA256: strings.ToLower(req.PortraitSHA256),
		DocumentType:   req.DocumentType,
		CreatedAt:      now,
		ExpiresAt:      now.Add(s.cfg.PendingTTL),
	}
	// A pending record outlives its deadline by TerminalTTL so the issuer's
	// GET reads `expired` rather than 404.
	if err := s.store.Create(r.Context(), sess, s.cfg.PendingTTL+s.cfg.TerminalTTL); err != nil {
		s.log.Error("store create", "err", err)
		writeError(w, http.StatusInternalServerError, "store unavailable")
		return
	}
	// Re-encoded so the engine gets canonical padded base64 whatever the
	// issuer sent.
	s.portraits.Put(id, base64.StdEncoding.EncodeToString(portrait), s.cfg.PendingTTL)

	s.log.Info("session created", "face_session_id", id, "document_type", req.DocumentType)
	writeJSON(w, http.StatusOK, createSessionResponse{
		FaceSessionID: id,
		Token:         token,
		ExpiresAt:     sess.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (s *server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	sess, err := s.store.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	if err != nil {
		s.log.Error("store get", "err", err)
		writeError(w, http.StatusInternalServerError, "store unavailable")
		return
	}
	writeJSON(w, http.StatusOK, sessionResponse{
		Status:         sess.StatusAt(s.now()),
		Passed:         sess.Passed,
		Distance:       sess.Distance,
		PortraitSHA256: sess.PortraitSHA256,
		Frames:         sess.Frames,
		DurationMs:     sess.DurationMs(),
	})
}

func (s *server) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.portraits.Delete(id)
	if err := s.store.Delete(r.Context(), id); err != nil {
		s.log.Error("store delete", "err", err)
		writeError(w, http.StatusInternalServerError, "store unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// newCredentials makes a session id ("fs_" + 16 random bytes hex) and a
// bearer token (32 random bytes, base64url), returning the token's SHA-256
// for storage.
func newCredentials() (id, token string, tokenHash []byte, err error) {
	var idBytes [16]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return "", "", nil, err
	}
	var tokenBytes [32]byte
	if _, err := rand.Read(tokenBytes[:]); err != nil {
		return "", "", nil, err
	}
	token = base64.RawURLEncoding.EncodeToString(tokenBytes[:])
	sum := sha256.Sum256([]byte(token))
	return "fs_" + hex.EncodeToString(idBytes[:]), token, sum[:], nil
}

// decodeBase64 accepts padded and unpadded standard base64.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Debug("write response", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
