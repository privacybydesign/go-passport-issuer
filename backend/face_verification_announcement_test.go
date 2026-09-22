package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go-passport-issuer/analytics"

	"github.com/stretchr/testify/require"
)

func startValidationWith(t *testing.T, state *ServerState) ValidatePassportResponse {
	t.Helper()
	return startValidationWithBody(t, state, "")
}

// startValidationWithBody posts the given raw body ("" for none) and expects
// a 200.
func startValidationWithBody(t *testing.T, state *ServerState, body string) ValidatePassportResponse {
	t.Helper()
	rec := postStartValidation(state, body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var response ValidatePassportResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	return response
}

func postStartValidation(state *ServerState, body string) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	rec := httptest.NewRecorder()
	handleStartValidatePassport(state, rec, httptest.NewRequest(http.MethodPost, "/api/start-validation", reader))
	return rec
}

func twoMethodState(allowPreference bool) (*ServerState, *capturingRecorder) {
	recorder := &capturingRecorder{}
	return &ServerState{
		tokenStorage:           NewInMemoryTokenStorage(),
		faceVerificationClient: NewRegulaFaceClient("http://regula-face-api:41101", testRegulaThreshold),
		regulaFaceApiPublicUrl: "https://faceapi.staging.yivi.app",
		faceMethods:            policy(on, on, allowPreference),
		irisClient:             newFakeIris(),
		irisVerifierPublicUrl:  "wss://iris-verifier.staging.yivi.app",
		recorder:               recorder,
	}, recorder
}

// TestStartValidationAnnouncesFaceVerification verifies enabled face
// verification is announced with the browser/app-reachable Face API origin —
// never the internal one the backend itself matches against.
func TestStartValidationAnnouncesFaceVerification(t *testing.T) {
	state := &ServerState{
		tokenStorage:           NewInMemoryTokenStorage(),
		faceVerificationClient: NewRegulaFaceClient("http://regula-face-api:41101", testRegulaThreshold),
		regulaFaceApiPublicUrl: "https://faceapi.staging.yivi.app",
	}

	response := startValidationWith(t, state)
	require.NotNil(t, response.FaceVerification)
	require.Equal(t, "https://faceapi.staging.yivi.app", response.FaceVerification.FaceApiUrl)
	// A wallet without a declaration is assigned Regula, and told so in a key
	// it ignores.
	require.Equal(t, FaceMethodRegula, response.FaceVerification.Method)
}

// A wallet from before the capability declaration (no body) gets exactly
// today's response plus the method key, and its session is stored with the
// Regula assignment.
func TestStartValidationOldWalletGetsRegula(t *testing.T) {
	state, recorder := twoMethodState(false)
	response := startValidationWith(t, state)

	require.Equal(t, FaceMethodRegula, response.FaceVerification.Method)
	require.Equal(t, "https://faceapi.staging.yivi.app", response.FaceVerification.FaceApiUrl)

	rec, err := loadSessionRecord(state.tokenStorage, response.SessionId)
	require.NoError(t, err)
	require.Equal(t, response.Nonce, rec.Nonce)
	require.Equal(t, FaceMethodRegula, rec.Method)
	require.False(t, rec.AssignedAt.IsZero())

	e := recorder.last(t)
	require.Equal(t, analytics.KindAssigned, e.Kind)
	require.Equal(t, FaceMethodRegula, e.Method)
	require.Equal(t, analytics.AttemptFirst, e.AttemptKind)
	require.Empty(t, e.Client.Platform)
}

// The Iris announcement names the method and carries no Face API URL, and
// the wallet's labels travel into the session record and the recording.
func TestStartValidationAnnouncesIris(t *testing.T) {
	state, recorder := twoMethodState(false)
	response := startValidationWithBody(t, state, `{
		"face_verification": {"capabilities": ["iris"], "previous_method": "iris", "attempt": 2},
		"client": {"platform": "ios", "flavor": "appstore", "app_version": "8.3.0"}
	}`)

	require.Equal(t, FaceMethodIris, response.FaceVerification.Method)
	require.Empty(t, response.FaceVerification.FaceApiUrl)
	require.NotContains(t, strings.ToLower(response.FaceVerification.FaceApiUrl), "faceapi")

	rec, err := loadSessionRecord(state.tokenStorage, response.SessionId)
	require.NoError(t, err)
	require.Equal(t, FaceMethodIris, rec.Method)
	require.Equal(t, 2, rec.Attempt)
	require.Equal(t, analytics.Client{Platform: "ios", Flavor: "appstore", AppVersion: "8.3.0"}, rec.Client)

	e := recorder.last(t)
	require.Equal(t, FaceMethodIris, e.Method)
	require.Equal(t, analytics.AttemptRetry, e.AttemptKind)
	require.Equal(t, "appstore", e.Client.Flavor)
}

// The staging-only tester override.
func TestStartValidationClientPreference(t *testing.T) {
	body := `{"face_verification": {"capabilities": ["regula", "iris"], "preferred_method": "iris"}}`

	state, _ := twoMethodState(true)
	require.Equal(t, FaceMethodIris, startValidationWithBody(t, state, body).FaceVerification.Method)

	state, _ = twoMethodState(false)
	// Not honoured: the draw decides. Pin it so the assertion is meaningful.
	state.faceMethods = policy(on, on, false, 0)
	require.Equal(t, FaceMethodRegula, startValidationWithBody(t, state, body).FaceVerification.Method)
}

// Bodies wallets might send that are not declarations: empty, null, or an
// empty object all mean "no declaration".
func TestStartValidationTolerantBodies(t *testing.T) {
	state, _ := twoMethodState(false)
	for _, body := range []string{"", "null", "{}", `{"face_verification": null}`, `{"face_verification": {"capabilities": []}}`} {
		response := startValidationWithBody(t, state, body)
		require.Equal(t, FaceMethodRegula, response.FaceVerification.Method, "body %q", body)
	}
	rec := postStartValidation(state, "{not json")
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// Nothing the wallet can run is enabled: 400 with the body old wallets already
// know how to show, and no session is left behind.
func TestStartValidationNoEnabledMethod(t *testing.T) {
	state, recorder := twoMethodState(false)
	state.faceMethods = policy(off, on, false)
	rec := postStartValidation(state, "")
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "update the Yivi app")
	require.Empty(t, state.tokenStorage.(*InMemoryTokenStorage).TokenMap)
	require.Empty(t, recorder.events)
}

// With face verification disabled the session is still a JSON record, without
// a method, and nothing is recorded.
func TestStartValidationDisabledStoresPlainSession(t *testing.T) {
	recorder := &capturingRecorder{}
	state := &ServerState{tokenStorage: NewInMemoryTokenStorage(), recorder: recorder}
	response := startValidationWithBody(t, state, `{"face_verification": {"capabilities": ["regula", "iris"]}}`)
	require.Nil(t, response.FaceVerification)
	rec, err := loadSessionRecord(state.tokenStorage, response.SessionId)
	require.NoError(t, err)
	require.Equal(t, SessionRecord{Nonce: response.Nonce}, rec)
	require.Empty(t, recorder.events)
}

// TestStartValidationOmitsAnnouncementWhenDisabled verifies the field is absent
// when face verification is disabled — absence is the app's signal to skip the
// whole face verification step, so it must not be present-but-empty.
func TestStartValidationOmitsAnnouncementWhenDisabled(t *testing.T) {
	state := &ServerState{
		tokenStorage: NewInMemoryTokenStorage(),
		// No faceVerificationClient → disabled; a leftover URL must not
		// resurrect the announcement.
		regulaFaceApiPublicUrl: "https://faceapi.staging.yivi.app",
	}

	rec := httptest.NewRecorder()
	handleStartValidatePassport(state, rec, httptest.NewRequest(http.MethodPost, "/api/start-validation", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotContains(t, rec.Body.String(), "face_verification",
		"the field must be omitted entirely, not null or empty")

	var response ValidatePassportResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	require.Nil(t, response.FaceVerification)
	require.NotEmpty(t, response.SessionId)
	require.NotEmpty(t, response.Nonce)
}

// TestStartValidationAnnouncementNeverLeaksInternalUrl pins the announcement to
// the public URL field: the internal Regula address must never reach an app.
func TestStartValidationAnnouncementNeverLeaksInternalUrl(t *testing.T) {
	state := &ServerState{
		tokenStorage:           NewInMemoryTokenStorage(),
		faceVerificationClient: NewRegulaFaceClient("http://regula-face-api:41101", testRegulaThreshold),
		regulaFaceApiPublicUrl: "https://faceapi.staging.yivi.app",
	}

	rec := httptest.NewRecorder()
	handleStartValidatePassport(state, rec, httptest.NewRequest(http.MethodPost, "/api/start-validation", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotContains(t, rec.Body.String(), "regula-face-api")
}

// An on-device assignment is announced as the method alone. There is nothing
// for the wallet to address — no Face API, no verifier — so a URL in this
// announcement would be a bug, and the session is stored with the assignment
// like any other.
func TestStartValidationAnnouncesIrisOndevice(t *testing.T) {
	state, recorder := twoMethodState(false)
	state.faceMethods = policyWith(ondeviceOnly, false)

	response := startValidationWithBody(t, state,
		`{"face_verification": {"capabilities": ["regula", "iris", "iris_ondevice"]}, "client": {"platform": "android", "flavor": "play", "app_version": "8.4.0"}}`)

	require.NotNil(t, response.FaceVerification)
	require.Equal(t, FaceMethodIrisOndevice, response.FaceVerification.Method)
	require.Empty(t, response.FaceVerification.FaceApiUrl)

	rec, err := loadSessionRecord(state.tokenStorage, response.SessionId)
	require.NoError(t, err)
	require.Equal(t, FaceMethodIrisOndevice, rec.Method)

	e := recorder.events[len(recorder.events)-1]
	require.Equal(t, analytics.KindAssigned, e.Kind)
	require.Equal(t, FaceMethodIrisOndevice, e.Method)
	require.Equal(t, "play", e.Client.Flavor)
}
