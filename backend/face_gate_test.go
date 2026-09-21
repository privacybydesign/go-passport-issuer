package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"go-passport-issuer/analytics"
	"go-passport-issuer/models"

	"github.com/stretchr/testify/require"
)

// fakeIrisClient is a configurable double for the verifier's internal API.
type fakeIrisClient struct {
	mu        sync.Mutex
	created   []string // portrait hashes handed to CreateSession
	nextID    string
	createErr error
	status    map[string]*IrisSessionStatus
	getErr    error
	deleted   []string
	healthErr error
}

func newFakeIris() *fakeIrisClient {
	return &fakeIrisClient{nextID: "fs_1", status: map[string]*IrisSessionStatus{}}
}

func (f *fakeIrisClient) CreateSession(_ context.Context, portraitBase64, portraitSha256, documentType string) (*IrisSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.created = append(f.created, portraitSha256)
	if _, ok := f.status[f.nextID]; !ok {
		f.status[f.nextID] = &IrisSessionStatus{Status: irisStatusPending, PortraitSha256: portraitSha256}
	}
	return &IrisSession{FaceSessionID: f.nextID, Token: "tok-" + f.nextID}, nil
}

func (f *fakeIrisClient) GetSession(_ context.Context, id string) (*IrisSessionStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	s, ok := f.status[id]
	if !ok {
		return nil, errors.New("iris verifier returned status 404")
	}
	return s, nil
}

func (f *fakeIrisClient) DeleteSession(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, id)
	return nil
}

func (f *fakeIrisClient) HealthCheck() error { return f.healthErr }

// complete marks the verifier session with a verdict.
func (f *fakeIrisClient) complete(id string, passed bool, distance float64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status[id] = &IrisSessionStatus{Status: irisStatusCompleted, Passed: &passed, Distance: &distance, Frames: 60, DurationMs: 4000}
}

func (f *fakeIrisClient) fail(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status[id] = &IrisSessionStatus{Status: irisStatusFailed}
}

// capturingRecorder keeps every event for assertions.
type capturingRecorder struct {
	mu     sync.Mutex
	events []analytics.Record
}

func (c *capturingRecorder) Record(_ context.Context, e analytics.Record) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *capturingRecorder) last(t *testing.T) analytics.Record {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	require.NotEmpty(t, c.events, "no event recorded")
	return c.events[len(c.events)-1]
}

var portrait = []byte("a portrait as read from the chip")

func irisState(t *testing.T) (*ServerState, *fakeIrisClient, *capturingRecorder) {
	t.Helper()
	iris := newFakeIris()
	rec := &capturingRecorder{}
	state := &ServerState{
		tokenStorage:          NewInMemoryTokenStorage(),
		faceMethods:           policy(on, on, false),
		irisClient:            iris,
		irisVerifierPublicUrl: "wss://iris-verifier.example",
		recorder:              rec,
		faceVerificationClient: &fakeFaceClient{
			livenessResp: &LivenessStatus{Confirmed: true},
			matchResp:    &FaceMatchResponse{Matched: true, Similarity: 0.9},
		},
	}
	return state, iris, rec
}

func irisInput(session SessionRecord, request models.ValidationRequest) faceGateInput {
	return faceGateInput{session: session, request: request, portrait: portrait, documentType: documentTypePassport}
}

func TestOpenIrisFaceSession(t *testing.T) {
	state, iris, _ := irisState(t)
	ann, err := openIrisFaceSession(context.Background(), state, "s1", portrait, documentTypePassport)
	require.NoError(t, err)
	require.Equal(t, "fs_1", ann.FaceSessionId)
	require.Equal(t, "wss://iris-verifier.example/stream/fs_1", ann.StreamUrl)
	require.Equal(t, "tok-fs_1", ann.Token)
	require.Equal(t, 600, ann.ExpiresIn)
	// The verifier got the hash of exactly the bytes it also got as portrait,
	// and the issuer remembered the binding.
	require.Equal(t, []string{portraitSha256Hex(portrait)}, iris.created)
	rec, err := retrieveFaceRecord(state.tokenStorage, "fs_1")
	require.NoError(t, err)
	require.Equal(t, "s1", rec.SessionID)
	require.Equal(t, portraitSha256Hex(portrait), rec.PortraitSha256)
	require.Equal(t, documentTypePassport, rec.DocumentType)
}

func TestOpenIrisFaceSessionFailures(t *testing.T) {
	state, iris, _ := irisState(t)
	_, err := openIrisFaceSession(context.Background(), state, "s1", nil, documentTypePassport)
	require.ErrorContains(t, err, "no portrait")

	iris.createErr = errors.New("verifier down")
	_, err = openIrisFaceSession(context.Background(), state, "s1", portrait, documentTypePassport)
	require.ErrorContains(t, err, "verifier down")

	_, err = openIrisFaceSession(context.Background(), &ServerState{tokenStorage: NewInMemoryTokenStorage()}, "s1", portrait, documentTypePassport)
	require.ErrorContains(t, err, "not configured")
}

// The Iris gate, case by case: missing evidence, wrong method's evidence,
// unknown session, foreign session, portrait mismatch, pending, failed,
// rejected, passed.
func TestIrisGate(t *testing.T) {
	session := SessionRecord{Nonce: "n", Method: FaceMethodIris, Client: analytics.Client{Platform: "android", Flavor: "play", AppVersion: "8.3.0"}}
	base := models.ValidationRequest{SessionId: "s1", Nonce: "n"}

	open := func(t *testing.T, state *ServerState, sessionID string) string {
		ann, err := openIrisFaceSession(context.Background(), state, sessionID, portrait, documentTypePassport)
		require.NoError(t, err)
		return ann.FaceSessionId
	}

	t.Run("missing face session id is evidence missing with the update body", func(t *testing.T) {
		state, _, rec := irisState(t)
		w := httptest.NewRecorder()
		require.False(t, gateFaceVerification(state, w, irisInput(session, base)))
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "update the Yivi app")
		e := rec.last(t)
		require.Equal(t, analytics.KindIssuance, e.Kind)
		require.Equal(t, FaceMethodIris, e.Method)
		require.Equal(t, analytics.OutcomeEvidenceMissing, e.Outcome)
		require.Equal(t, documentTypePassport, e.DocumentType)
		require.Equal(t, "play", e.Client.Flavor)
	})

	t.Run("a liveness transaction on an iris session is an assignment mismatch", func(t *testing.T) {
		state, _, rec := irisState(t)
		req := base
		req.LivenessTransactionId = "txn-1"
		w := httptest.NewRecorder()
		require.False(t, gateFaceVerification(state, w, irisInput(session, req)))
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "assigned method")
		require.Equal(t, analytics.OutcomeAssignmentMismatch, rec.last(t).Outcome)
	})

	t.Run("unknown face session", func(t *testing.T) {
		state, _, rec := irisState(t)
		req := base
		req.FaceSessionId = "fs_unknown"
		w := httptest.NewRecorder()
		require.False(t, gateFaceVerification(state, w, irisInput(session, req)))
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Equal(t, faceVerificationFailedBody, w.Body.String())
		require.Equal(t, analytics.OutcomeEvidenceMissing, rec.last(t).Outcome)
	})

	t.Run("face session of another document session", func(t *testing.T) {
		state, iris, rec := irisState(t)
		id := open(t, state, "other-session")
		iris.complete(id, true, 0.3)
		req := base
		req.FaceSessionId = id
		w := httptest.NewRecorder()
		require.False(t, gateFaceVerification(state, w, irisInput(session, req)))
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Equal(t, analytics.OutcomeEvidenceMissing, rec.last(t).Outcome)
	})

	t.Run("portrait of another document", func(t *testing.T) {
		state, iris, rec := irisState(t)
		id := open(t, state, "s1")
		iris.complete(id, true, 0.3)
		req := base
		req.FaceSessionId = id
		in := irisInput(session, req)
		in.portrait = []byte("a different portrait")
		w := httptest.NewRecorder()
		require.False(t, gateFaceVerification(state, w, in))
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Equal(t, analytics.OutcomeAssignmentMismatch, rec.last(t).Outcome)
		// The verdict stays: nothing was consumed for a document it was not
		// obtained against.
		require.Empty(t, iris.deleted)
	})

	t.Run("pending session is not evidence", func(t *testing.T) {
		state, _, rec := irisState(t)
		id := open(t, state, "s1")
		req := base
		req.FaceSessionId = id
		w := httptest.NewRecorder()
		require.False(t, gateFaceVerification(state, w, irisInput(session, req)))
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Equal(t, faceVerificationFailedBody, w.Body.String())
		require.Equal(t, analytics.OutcomeEvidenceMissing, rec.last(t).Outcome)
	})

	t.Run("failed session", func(t *testing.T) {
		state, iris, rec := irisState(t)
		id := open(t, state, "s1")
		iris.fail(id)
		req := base
		req.FaceSessionId = id
		w := httptest.NewRecorder()
		require.False(t, gateFaceVerification(state, w, irisInput(session, req)))
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Equal(t, analytics.OutcomeLivenessRejected, rec.last(t).Outcome)
	})

	t.Run("completed but not passed", func(t *testing.T) {
		state, iris, rec := irisState(t)
		id := open(t, state, "s1")
		iris.complete(id, false, 0.91)
		req := base
		req.FaceSessionId = id
		w := httptest.NewRecorder()
		require.False(t, gateFaceVerification(state, w, irisInput(session, req)))
		require.Equal(t, http.StatusBadRequest, w.Code)
		e := rec.last(t)
		require.Equal(t, analytics.OutcomeMatchRejected, e.Outcome)
		require.NotNil(t, e.Score)
		require.InDelta(t, 0.91, *e.Score, 1e-9)
		require.Equal(t, analytics.ScoreIrisDistance, e.ScoreKind)
	})

	t.Run("verifier unreachable", func(t *testing.T) {
		state, iris, rec := irisState(t)
		id := open(t, state, "s1")
		iris.getErr = errors.New("connection refused")
		req := base
		req.FaceSessionId = id
		w := httptest.NewRecorder()
		require.False(t, gateFaceVerification(state, w, irisInput(session, req)))
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Equal(t, analytics.OutcomeError, rec.last(t).Outcome)
	})

	t.Run("passed: issuance proceeds and nothing outlives it", func(t *testing.T) {
		state, iris, rec := irisState(t)
		id := open(t, state, "s1")
		iris.complete(id, true, 0.41)
		req := base
		req.FaceSessionId = id
		req.FaceAttempt = 2
		req.FaceDurationMs = 4200
		w := httptest.NewRecorder()
		require.True(t, gateFaceVerification(state, w, irisInput(session, req)))
		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, []string{id}, iris.deleted)
		_, err := retrieveFaceRecord(state.tokenStorage, id)
		require.Error(t, err)

		e := rec.last(t)
		require.Equal(t, analytics.OutcomePassed, e.Outcome)
		require.InDelta(t, 0.41, *e.Score, 1e-9)
		require.Equal(t, analytics.ScoreIrisDistance, e.ScoreKind)
		require.EqualValues(t, 4200, *e.DurationMs)
		// The wallet reported a second attempt, so the record's first-attempt
		// label is overridden.
		require.Equal(t, analytics.AttemptRetry, e.AttemptKind)
	})
}

// The Regula gate through the per-method entry point, including the
// mismatch case and the recordings it did not have before.
func TestRegulaGateThroughMethodDispatch(t *testing.T) {
	session := SessionRecord{Nonce: "n", Method: FaceMethodRegula}
	base := models.ValidationRequest{SessionId: "s1", Nonce: "n", LivenessTransactionId: "txn-1", FaceDurationMs: 3000}

	t.Run("passes and records the similarity", func(t *testing.T) {
		state, _, rec := irisState(t)
		w := httptest.NewRecorder()
		require.True(t, gateFaceVerification(state, w, irisInput(session, base)))
		e := rec.last(t)
		require.Equal(t, FaceMethodRegula, e.Method)
		require.Equal(t, analytics.OutcomePassed, e.Outcome)
		require.InDelta(t, 0.9, *e.Score, 1e-9)
		require.Equal(t, analytics.ScoreRegulaSimilarity, e.ScoreKind)
		require.EqualValues(t, 3000, *e.DurationMs)
		require.Equal(t, analytics.AttemptFirst, e.AttemptKind)
	})

	t.Run("a face session id on a regula session is an assignment mismatch", func(t *testing.T) {
		state, _, rec := irisState(t)
		req := base
		req.FaceSessionId = "fs_1"
		w := httptest.NewRecorder()
		require.False(t, gateFaceVerification(state, w, irisInput(session, req)))
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Equal(t, analytics.OutcomeAssignmentMismatch, rec.last(t).Outcome)
	})

	t.Run("missing transaction id", func(t *testing.T) {
		state, _, rec := irisState(t)
		req := base
		req.LivenessTransactionId = ""
		w := httptest.NewRecorder()
		require.False(t, gateFaceVerification(state, w, irisInput(session, req)))
		require.Contains(t, w.Body.String(), "update the Yivi app")
		require.Equal(t, analytics.OutcomeEvidenceMissing, rec.last(t).Outcome)
	})

	t.Run("liveness not confirmed", func(t *testing.T) {
		state, _, rec := irisState(t)
		state.faceVerificationClient = &fakeFaceClient{livenessResp: &LivenessStatus{Confirmed: false, Code: 7}}
		w := httptest.NewRecorder()
		require.False(t, gateFaceVerification(state, w, irisInput(session, base)))
		require.Equal(t, analytics.OutcomeLivenessRejected, rec.last(t).Outcome)
	})

	t.Run("match rejected", func(t *testing.T) {
		state, _, rec := irisState(t)
		state.faceVerificationClient = &fakeFaceClient{
			livenessResp: &LivenessStatus{Confirmed: true},
			matchResp:    &FaceMatchResponse{Matched: false, Similarity: 0.2},
		}
		w := httptest.NewRecorder()
		require.False(t, gateFaceVerification(state, w, irisInput(session, base)))
		e := rec.last(t)
		require.Equal(t, analytics.OutcomeMatchRejected, e.Outcome)
		require.InDelta(t, 0.2, *e.Score, 1e-9)
	})

	t.Run("a legacy session without a method is regula", func(t *testing.T) {
		state, _, rec := irisState(t)
		w := httptest.NewRecorder()
		require.True(t, gateFaceVerification(state, w, irisInput(SessionRecord{Nonce: "n"}, base)))
		require.Equal(t, FaceMethodRegula, rec.last(t).Method)
	})

	t.Run("disabled skips and records nothing", func(t *testing.T) {
		rec := &capturingRecorder{}
		state := &ServerState{recorder: rec, tokenStorage: NewInMemoryTokenStorage()}
		w := httptest.NewRecorder()
		require.True(t, gateFaceVerification(state, w, irisInput(session, base)))
		require.Empty(t, rec.events)
	})
}
