package main

import (
	"testing"
	"time"

	"go-passport-issuer/analytics"

	"github.com/stretchr/testify/require"
)

func TestSessionRecordRoundTrip(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	rec := SessionRecord{
		Nonce:      "abcd",
		Method:     FaceMethodIris,
		AssignedAt: time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC),
		Attempt:    2,
		Client:     analytics.Client{Platform: "ios", Flavor: "appstore", AppVersion: "8.3.0"},
	}
	require.NoError(t, storeSessionRecord(storage, "s1", rec))

	got, err := validateSession(storage, "s1", "abcd")
	require.NoError(t, err)
	require.Equal(t, rec, got)
	require.Equal(t, analytics.AttemptRetry, got.attemptKind())
}

// A bare nonce is what issuers before this record stored (and what an older
// replica stores during a rollout): it must still validate, as a session
// without an assignment.
func TestSessionRecordReadsLegacyBareNonce(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	require.NoError(t, storage.StoreToken("s1", "abcd"))

	got, err := validateSession(storage, "s1", "abcd")
	require.NoError(t, err)
	require.Equal(t, SessionRecord{Nonce: "abcd"}, got)
	require.Equal(t, analytics.AttemptFirst, got.attemptKind())

	_, err = validateSession(storage, "s1", "wrong")
	require.ErrorContains(t, err, ERR_INVALID_NONCE_SESSION)
}

func TestSessionRecordMissingOrMalformed(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	_, err := validateSession(storage, "missing", "abcd")
	require.ErrorContains(t, err, ERR_TOKEN_RETRIEVAL)

	require.NoError(t, storage.StoreToken("bad", "{not json"))
	_, err = validateSession(storage, "bad", "abcd")
	require.Error(t, err)
}

// The stored record never carries an empty method or zero time: an issuer
// with face verification disabled stores just the nonce in JSON.
func TestSessionRecordOmitsUnsetFields(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	require.NoError(t, storeSessionRecord(storage, "s1", SessionRecord{Nonce: "abcd"}))
	raw, err := storage.RetrieveToken("s1")
	require.NoError(t, err)
	require.JSONEq(t, `{"nonce":"abcd"}`, raw)
}

func TestFaceRecordRoundTrip(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	rec := FaceRecord{
		FaceSessionID:  "fs_1",
		SessionID:      "s1",
		PortraitSha256: portraitSha256Hex([]byte("portrait")),
		DocumentType:   documentTypePassport,
		CreatedAt:      time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC),
	}
	require.NoError(t, storeFaceRecord(storage, rec))
	got, err := retrieveFaceRecord(storage, "fs_1")
	require.NoError(t, err)
	require.Equal(t, rec, got)

	// Face records live beside session records without colliding.
	_, err = storage.RetrieveToken("fs_1")
	require.Error(t, err)

	require.NoError(t, deleteFaceRecord(storage, "fs_1"))
	_, err = retrieveFaceRecord(storage, "fs_1")
	require.Error(t, err)
}

func TestPortraitSha256Hex(t *testing.T) {
	require.Equal(t,
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		portraitSha256Hex(nil))
	require.Len(t, portraitSha256Hex([]byte("x")), 64)
}
