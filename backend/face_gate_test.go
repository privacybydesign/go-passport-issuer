package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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
	// threshold stands in for the one HTTPIrisClient applies to a completed
	// session's distance; a test moves it to put the issuer's decision and the
	// verifier's apart.
	threshold float64
}

func newFakeIris() *fakeIrisClient {
	return &fakeIrisClient{nextID: "fs_1", status: map[string]*IrisSessionStatus{}, threshold: testIrisThreshold}
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

// complete marks the verifier session with a verdict: passed is the
// verifier's own decision, and Match is the issuer's, which the real client
// derives from the distance the same way.
func (f *fakeIrisClient) complete(id string, passed bool, distance float64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status[id] = &IrisSessionStatus{
		Status:     irisStatusCompleted,
		Passed:     &passed,
		Distance:   &distance,
		Match:      &FaceMatchVerdict{Score: distance, Matched: distance <= f.threshold},
		Frames:     60,
		DurationMs: 4000,
	}
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
			matchResp:    &FaceMatchVerdict{Matched: true, Score: 0.9},
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

	t.Run("a stricter issuer refuses what the verifier passed", func(t *testing.T) {
		state, iris, rec := irisState(t)
		// The verifier passed the session on its own threshold; this issuer is
		// configured stricter, and its decision is the one that gates.
		iris.threshold = 0.5
		id := open(t, state, "s1")
		iris.complete(id, true, 0.61)
		req := base
		req.FaceSessionId = id
		w := httptest.NewRecorder()
		require.False(t, gateFaceVerification(state, w, irisInput(session, req)))
		require.Equal(t, http.StatusBadRequest, w.Code)
		e := rec.last(t)
		require.Equal(t, analytics.OutcomeMatchRejected, e.Outcome)
		require.InDelta(t, 0.61, *e.Score, 1e-9)
		// Nothing is deleted: the session was not spent on a pass.
		require.Empty(t, iris.deleted)
	})

	t.Run("a laxer issuer accepts what the verifier did not pass", func(t *testing.T) {
		state, iris, rec := irisState(t)
		iris.threshold = 0.95
		id := open(t, state, "s1")
		iris.complete(id, false, 0.91)
		req := base
		req.FaceSessionId = id
		w := httptest.NewRecorder()
		require.True(t, gateFaceVerification(state, w, irisInput(session, req)))
		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, analytics.OutcomePassed, rec.last(t).Outcome)
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
			matchResp:    &FaceMatchVerdict{Matched: false, Score: 0.2},
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

func ondeviceState(t *testing.T) (*ServerState, *capturingRecorder) {
	t.Helper()
	rec := &capturingRecorder{}
	// No Iris client and no Regula client: this method reaches neither, which
	// is the point of it.
	return &ServerState{
		tokenStorage: NewInMemoryTokenStorage(),
		faceMethods:  policyWith(allThreeOn, false),
		recorder:     rec,
	}, rec
}

func ondeviceInput(session SessionRecord, request models.ValidationRequest) faceGateInput {
	return faceGateInput{session: session, request: request, portrait: portrait, documentType: documentTypePassport}
}

func verdict(passed bool) *bool { return &passed }

// The on-device gate, case by case. It cannot check the verdict — that is the
// accepted trade — so what is tested here is everything around it: that a
// verdict was given, that a passing one is tied to this document's portrait,
// and that a failing one is recorded rather than turned into something else.
func TestIrisOndeviceGate(t *testing.T) {
	session := SessionRecord{Nonce: "n", Method: FaceMethodIrisOndevice, Client: analytics.Client{Platform: "android", Flavor: "play", AppVersion: "8.4.0"}}
	base := models.ValidationRequest{SessionId: "s1", Nonce: "n"}
	hash := portraitSha256Hex(portrait)

	t.Run("no verdict is evidence missing with the update body", func(t *testing.T) {
		state, rec := ondeviceState(t)
		w := httptest.NewRecorder()
		require.False(t, gateFaceVerification(state, w, ondeviceInput(session, base)))
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "update the Yivi app")
		e := rec.last(t)
		require.Equal(t, analytics.KindIssuance, e.Kind)
		require.Equal(t, FaceMethodIrisOndevice, e.Method)
		require.Equal(t, analytics.OutcomeEvidenceMissing, e.Outcome)
		require.Equal(t, "play", e.Client.Flavor)
	})

	t.Run("a passing verdict for this portrait is issued on", func(t *testing.T) {
		state, rec := ondeviceState(t)
		req := base
		req.FaceOndevicePassed = verdict(true)
		req.FaceOndevicePortraitSha256 = hash
		w := httptest.NewRecorder()
		require.True(t, gateFaceVerification(state, w, ondeviceInput(session, req)))
		require.Equal(t, http.StatusOK, w.Code)
		e := rec.last(t)
		require.Equal(t, analytics.OutcomePassed, e.Outcome)
		// A wallet that reports no distance records no score, as before.
		require.Nil(t, e.Score)
		require.Empty(t, string(e.ScoreKind))
	})

	// The distance is recorded for its own sake: the issuer gates on the
	// verdict alone, so the number changes no decision, and it is kept on its
	// own scale name because nothing here measured it.
	t.Run("a reported distance is recorded under its own score kind", func(t *testing.T) {
		state, rec := ondeviceState(t)
		req := base
		req.FaceOndevicePassed = verdict(true)
		req.FaceOndevicePortraitSha256 = hash
		req.FaceOndeviceDistance = analytics.Float64(0.41)
		w := httptest.NewRecorder()
		require.True(t, gateFaceVerification(state, w, ondeviceInput(session, req)))
		e := rec.last(t)
		require.Equal(t, analytics.OutcomePassed, e.Outcome)
		require.NotNil(t, e.Score)
		require.InDelta(t, 0.41, *e.Score, 1e-9)
		require.Equal(t, analytics.ScoreIrisOndeviceDistance, e.ScoreKind)
		// Never the verifier's kind: that one means a distance this issuer
		// measured from frames it saw.
		require.NotEqual(t, analytics.ScoreIrisDistance, e.ScoreKind)
	})

	// Recorded whatever the outcome, which is the point of recording it: a
	// distance is as interesting on a rejection as on a pass, and a passing
	// verdict carrying an implausible one is only visible this way.
	t.Run("a distance is recorded on a rejection too", func(t *testing.T) {
		state, rec := ondeviceState(t)
		req := base
		req.FaceOndevicePassed = verdict(false)
		req.FaceOndevicePortraitSha256 = hash
		req.FaceOndeviceDistance = analytics.Float64(0.93)
		w := httptest.NewRecorder()
		require.False(t, gateFaceVerification(state, w, ondeviceInput(session, req)))
		e := rec.last(t)
		require.Equal(t, analytics.OutcomeLivenessRejected, e.Outcome)
		require.InDelta(t, 0.93, *e.Score, 1e-9)
		require.Equal(t, analytics.ScoreIrisOndeviceDistance, e.ScoreKind)
	})

	// A distance a threshold would have refused still passes: the verdict is
	// what gates, and the number is never acted on.
	t.Run("the distance changes no decision", func(t *testing.T) {
		state, rec := ondeviceState(t)
		req := base
		req.FaceOndevicePassed = verdict(true)
		req.FaceOndevicePortraitSha256 = hash
		req.FaceOndeviceDistance = analytics.Float64(0.99)
		w := httptest.NewRecorder()
		require.True(t, gateFaceVerification(state, w, ondeviceInput(session, req)))
		require.Equal(t, analytics.OutcomePassed, rec.last(t).Outcome)
	})

	t.Run("an uppercase hash is the same hash", func(t *testing.T) {
		state, _ := ondeviceState(t)
		req := base
		req.FaceOndevicePassed = verdict(true)
		req.FaceOndevicePortraitSha256 = strings.ToUpper(hash)
		w := httptest.NewRecorder()
		require.True(t, gateFaceVerification(state, w, ondeviceInput(session, req)))
	})

	t.Run("a failing verdict is recorded as a rejection, not swallowed", func(t *testing.T) {
		state, rec := ondeviceState(t)
		req := base
		req.FaceOndevicePassed = verdict(false)
		req.FaceOndevicePortraitSha256 = hash
		w := httptest.NewRecorder()
		require.False(t, gateFaceVerification(state, w, ondeviceInput(session, req)))
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Equal(t, faceVerificationFailedBody, w.Body.String())
		require.Equal(t, analytics.OutcomeLivenessRejected, rec.last(t).Outcome)
	})

	// A failure grants nothing, so it is recorded as the failure it is even
	// when the wallet sent no portrait hash with it. Only a pass has to be
	// tied to a document.
	t.Run("a failing verdict without a hash is still a rejection", func(t *testing.T) {
		state, rec := ondeviceState(t)
		req := base
		req.FaceOndevicePassed = verdict(false)
		w := httptest.NewRecorder()
		require.False(t, gateFaceVerification(state, w, ondeviceInput(session, req)))
		require.Equal(t, analytics.OutcomeLivenessRejected, rec.last(t).Outcome)
	})

	t.Run("a pass obtained against another document is refused", func(t *testing.T) {
		state, rec := ondeviceState(t)
		req := base
		req.FaceOndevicePassed = verdict(true)
		req.FaceOndevicePortraitSha256 = portraitSha256Hex([]byte("a different portrait"))
		w := httptest.NewRecorder()
		require.False(t, gateFaceVerification(state, w, ondeviceInput(session, req)))
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Equal(t, analytics.OutcomeAssignmentMismatch, rec.last(t).Outcome)
	})

	t.Run("a pass with no hash at all is refused", func(t *testing.T) {
		state, rec := ondeviceState(t)
		req := base
		req.FaceOndevicePassed = verdict(true)
		w := httptest.NewRecorder()
		require.False(t, gateFaceVerification(state, w, ondeviceInput(session, req)))
		require.Equal(t, analytics.OutcomeAssignmentMismatch, rec.last(t).Outcome)
	})

	t.Run("a pass for a document that carried no portrait is refused", func(t *testing.T) {
		state, rec := ondeviceState(t)
		req := base
		req.FaceOndevicePassed = verdict(true)
		req.FaceOndevicePortraitSha256 = hash
		in := ondeviceInput(session, req)
		in.portrait = nil
		w := httptest.NewRecorder()
		require.False(t, gateFaceVerification(state, w, in))
		require.Equal(t, analytics.OutcomeAssignmentMismatch, rec.last(t).Outcome)
	})
}

// Evidence belonging to another method is refused whichever way round it is,
// now that three methods can be assigned.
func TestForeignEvidenceAcrossMethods(t *testing.T) {
	base := models.ValidationRequest{SessionId: "s1", Nonce: "n"}

	cases := []struct {
		name    string
		method  FaceMethod
		mutate  func(*models.ValidationRequest)
		carries string
	}{
		{"liveness transaction on an on-device session", FaceMethodIrisOndevice,
			func(r *models.ValidationRequest) { r.LivenessTransactionId = "txn-1" }, "liveness transaction id"},
		{"face session on an on-device session", FaceMethodIrisOndevice,
			func(r *models.ValidationRequest) { r.FaceSessionId = "fs_1" }, "face session id"},
		{"on-device verdict on a regula session", FaceMethodRegula,
			func(r *models.ValidationRequest) { r.FaceOndevicePassed = verdict(true) }, "on-device face verdict"},
		{"on-device verdict on an iris session", FaceMethodIris,
			func(r *models.ValidationRequest) { r.FaceOndevicePassed = verdict(true) }, "on-device face verdict"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state, rec := ondeviceState(t)
			req := base
			tc.mutate(&req)
			w := httptest.NewRecorder()
			in := ondeviceInput(SessionRecord{Nonce: "n", Method: tc.method}, req)
			require.False(t, gateFaceVerification(state, w, in))
			require.Equal(t, http.StatusBadRequest, w.Code)
			require.Contains(t, w.Body.String(), "assigned method")
			e := rec.last(t)
			require.Equal(t, analytics.OutcomeAssignmentMismatch, e.Outcome)
			require.Equal(t, tc.method, e.Method)
		})
	}

	t.Run("a session assigned a method this issuer does not know is an internal error", func(t *testing.T) {
		state, rec := ondeviceState(t)
		w := httptest.NewRecorder()
		require.False(t, gateFaceVerification(state, w, ondeviceInput(SessionRecord{Nonce: "n", Method: "holo"}, base)))
		require.Equal(t, http.StatusInternalServerError, w.Code)
		require.Equal(t, analytics.OutcomeError, rec.last(t).Outcome)
	})
}
