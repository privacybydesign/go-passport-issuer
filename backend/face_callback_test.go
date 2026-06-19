package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// pythonCanonicalSign mirrors the face verification service's signing exactly:
// HMAC-SHA256(binding_secret, json.dumps(payload, sort_keys=True,
// separators=(",", ":"))), hex-encoded. The canonical string is typed out here
// (sorted keys, compact) so the test is independent of the production
// canonicalJSON implementation.
func pythonCanonicalSign(secret, canonical string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

const (
	testFaceSessionID = "fs_test"
	testBindingSecret = "super-secret-binding"
	// DG2 raw bytes -> hex, and their SHA256 (matches the face service salt).
	testDG2Hex = "deadbeef0102"
)

func testDG2Sha256() string {
	raw, _ := hex.DecodeString(testDG2Hex)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// fakeStatusGetter is the pull-fallback double.
type fakeStatusGetter struct {
	res    *FaceVerificationResult
	err    error
	called bool
}

func (f *fakeStatusGetter) GetSessionStatus(_ context.Context, _ string) (*FaceVerificationResult, error) {
	f.called = true
	return f.res, f.err
}

func seedFaceRecord(t *testing.T, storage TokenStorage, status string) {
	t.Helper()
	require.NoError(t, storeFaceRecord(storage, &FaceRecord{
		FaceSessionID: testFaceSessionID,
		SessionID:     "any",
		BindingSecret: testBindingSecret,
		Dg2Sha256:     testDG2Sha256(),
		Status:        status,
	}))
}

// --- Callback signature -----------------------------------------------------

func TestFaceCallbackValidSignatureRecordsResult(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage)
	seedFaceRecord(t, storage, faceStatusPending)

	// Canonical form: top-level keys sorted (details, face_session_id, result,
	// timestamp); details keys sorted.
	canonical := `{"details":{"frames_processed":42,"liveness_passed":true,"liveness_score":0.9,"match_confidence":0.97,"verification_duration_ms":1234},"face_session_id":"fs_test","result":"success","timestamp":"2026-06-19T12:00:00+00:00"}`
	sig := pythonCanonicalSign(testBindingSecret, canonical)

	// Wire body: arbitrary key order + the signature field. The handler sorts.
	body := `{"face_session_id":"fs_test","result":"success","timestamp":"2026-06-19T12:00:00+00:00","details":{"match_confidence":0.97,"liveness_passed":true,"liveness_score":0.9,"frames_processed":42,"verification_duration_ms":1234},"signature":"` + sig + `"}`

	resp, err := http.Post("http://localhost:8081/api/face/callback", "application/json", strings.NewReader(body))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	rec, err := retrieveFaceRecord(storage, testFaceSessionID)
	require.NoError(t, err)
	require.Equal(t, faceStatusSuccess, rec.Status)
	require.NotNil(t, rec.MatchConfidence)
	require.InDelta(t, 0.97, *rec.MatchConfidence, 1e-9)
	require.NotNil(t, rec.LivenessPassed)
	require.True(t, *rec.LivenessPassed)
}

func TestFaceCallbackBadSignatureRejected(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage)
	seedFaceRecord(t, storage, faceStatusPending)

	body := `{"face_session_id":"fs_test","result":"success","timestamp":"t","details":{},"signature":"deadbeef"}`
	resp, err := http.Post("http://localhost:8081/api/face/callback", "application/json", strings.NewReader(body))
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	_ = resp.Body.Close()

	// Status must be unchanged.
	rec, err := retrieveFaceRecord(storage, testFaceSessionID)
	require.NoError(t, err)
	require.Equal(t, faceStatusPending, rec.Status)
}

func TestFaceCallbackUnknownSession(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage)

	body := `{"face_session_id":"fs_missing","result":"success","timestamp":"t","details":{},"signature":"x"}`
	resp, err := http.Post("http://localhost:8081/api/face/callback", "application/json", strings.NewReader(body))
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	_ = resp.Body.Close()
}

// --- Issuance gate ----------------------------------------------------------

func issueReq(session, nonce string) any {
	r := newReq(session, nonce, withDG("DG2", testDG2Hex))
	r.FaceSessionId = testFaceSessionID
	return r
}

func TestIssueGatedSuccess(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage, func(s *ServerState) { s.requireFaceForIssuance = true })
	seedFaceRecord(t, storage, faceStatusSuccess)

	session, nonce := startValidation(t)
	resp, body, decoded := postJSON[IssuanceResponse](t, "http://localhost:8081/api/issue-passport", issueReq(session, nonce))
	mustStatus(t, resp, http.StatusOK, body)
	require.Equal(t, "test-jwt", decoded.Jwt)
}

func TestIssueGatedFailedVerdict(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage, func(s *ServerState) { s.requireFaceForIssuance = true })
	seedFaceRecord(t, storage, "failed")

	session, nonce := startValidation(t)
	resp, body, _ := postJSON[IssuanceResponse](t, "http://localhost:8081/api/issue-passport", issueReq(session, nonce))
	mustStatus(t, resp, http.StatusForbidden, body)
	require.Contains(t, string(body), faceGateFailed)
}

func TestIssueGatedMissingFaceSessionID(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage, func(s *ServerState) { s.requireFaceForIssuance = true })

	session, nonce := startValidation(t)
	req := newReq(session, nonce, withDG("DG2", testDG2Hex)) // no FaceSessionId
	resp, body, _ := postJSON[IssuanceResponse](t, "http://localhost:8081/api/issue-passport", req)
	mustStatus(t, resp, http.StatusForbidden, body)
	require.Contains(t, string(body), faceGateRequired)
}

func TestIssueGatedDG2Mismatch(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage, func(s *ServerState) { s.requireFaceForIssuance = true })
	seedFaceRecord(t, storage, faceStatusSuccess)

	session, nonce := startValidation(t)
	req := newReq(session, nonce, withDG("DG2", "00ff")) // different DG2 -> different hash
	req.FaceSessionId = testFaceSessionID
	resp, body, _ := postJSON[IssuanceResponse](t, "http://localhost:8081/api/issue-passport", req)
	mustStatus(t, resp, http.StatusForbidden, body)
	require.Contains(t, string(body), faceGateMismatch)
}

func TestIssueGatedPendingNoGetter(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage, func(s *ServerState) { s.requireFaceForIssuance = true })
	seedFaceRecord(t, storage, faceStatusPending)

	session, nonce := startValidation(t)
	resp, body, _ := postJSON[IssuanceResponse](t, "http://localhost:8081/api/issue-passport", issueReq(session, nonce))
	mustStatus(t, resp, http.StatusPreconditionRequired, body)
	require.Contains(t, string(body), faceGatePending)
}

func TestIssueGatedPendingPollFallbackSucceeds(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	getter := &fakeStatusGetter{res: &FaceVerificationResult{Status: faceStatusSuccess}}
	startTestServer(t, storage, func(s *ServerState) {
		s.requireFaceForIssuance = true
		s.faceStatusGetter = getter
	})
	seedFaceRecord(t, storage, faceStatusPending)

	session, nonce := startValidation(t)
	resp, body, decoded := postJSON[IssuanceResponse](t, "http://localhost:8081/api/issue-passport", issueReq(session, nonce))
	mustStatus(t, resp, http.StatusOK, body)
	require.True(t, getter.called)
	require.Equal(t, "test-jwt", decoded.Jwt)
}

// Driving licences bind on the DG6 portrait (not DG2). The same gate applies to
// issue-driving-licence. Reuses the test portrait bytes under the DG6 key, so
// the seeded record's hash matches.
func TestIssueDrivingLicenceGatedSuccess(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage, func(s *ServerState) { s.requireFaceForIssuance = true })
	seedFaceRecord(t, storage, faceStatusSuccess)

	session, nonce := startValidation(t)
	r := newReq(session, nonce, withDG("DG6", testDG2Hex))
	r.FaceSessionId = testFaceSessionID
	resp, body, decoded := postJSON[IssuanceResponse](t, "http://localhost:8081/api/issue-driving-licence", r)
	mustStatus(t, resp, http.StatusOK, body)
	require.Equal(t, "test-jwt", decoded.Jwt)
}

func TestIssueDrivingLicenceGatedFailedVerdict(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage, func(s *ServerState) { s.requireFaceForIssuance = true })
	seedFaceRecord(t, storage, "failed")

	session, nonce := startValidation(t)
	r := newReq(session, nonce, withDG("DG6", testDG2Hex))
	r.FaceSessionId = testFaceSessionID
	resp, body, _ := postJSON[IssuanceResponse](t, "http://localhost:8081/api/issue-driving-licence", r)
	mustStatus(t, resp, http.StatusForbidden, body)
	require.Contains(t, string(body), faceGateFailed)
}

// Backwards compatibility: with face verification not required, issuance works
// exactly as before — no face_session_id needed.
func TestIssueUngatedWhenFaceNotRequired(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage) // requireFaceForIssuance defaults to false

	session, nonce := startValidation(t)
	req := newReq(session, nonce)
	resp, body, decoded := postJSON[IssuanceResponse](t, "http://localhost:8081/api/issue-passport", req)
	mustStatus(t, resp, http.StatusOK, body)
	require.Equal(t, "test-jwt", decoded.Jwt)
}
