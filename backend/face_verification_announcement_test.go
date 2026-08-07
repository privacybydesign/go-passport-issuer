package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func startValidationWith(t *testing.T, state *ServerState) ValidatePassportResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	handleStartValidatePassport(state, rec, httptest.NewRequest(http.MethodPost, "/api/start-validation", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var response ValidatePassportResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	return response
}

// TestStartValidationAnnouncesFaceVerification verifies a non-disabled policy
// announces face verification with the browser/app-reachable Face API origin —
// never the internal one the backend itself matches against.
func TestStartValidationAnnouncesFaceVerification(t *testing.T) {
	for _, policy := range []FaceVerificationPolicy{
		FaceVerificationOptional, FaceVerificationRequired,
	} {
		state := &ServerState{
			tokenStorage:           NewInMemoryTokenStorage(),
			faceVerificationClient: NewRegulaFaceClient("http://regula-face-api:41101", 0),
			faceVerificationPolicy: policy,
			regulaFaceApiPublicUrl: "https://faceapi.staging.yivi.app",
		}

		response := startValidationWith(t, state)
		require.NotNil(t, response.FaceVerification, policy)
		require.Equal(t, "https://faceapi.staging.yivi.app", response.FaceVerification.FaceApiUrl)
	}
}

// TestStartValidationOmitsAnnouncementWhenDisabled verifies the field is absent
// under a disabled policy — absence is the app's signal to skip the whole face
// verification step, so it must not be present-but-empty.
func TestStartValidationOmitsAnnouncementWhenDisabled(t *testing.T) {
	state := &ServerState{
		tokenStorage:           NewInMemoryTokenStorage(),
		faceVerificationPolicy: FaceVerificationDisabled,
		// Leftover URL must not resurrect the announcement.
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
		faceVerificationClient: NewRegulaFaceClient("http://regula-face-api:41101", 0),
		faceVerificationPolicy: FaceVerificationRequired,
		regulaFaceApiPublicUrl: "https://faceapi.staging.yivi.app",
	}

	rec := httptest.NewRecorder()
	handleStartValidatePassport(state, rec, httptest.NewRequest(http.MethodPost, "/api/start-validation", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotContains(t, rec.Body.String(), "regula-face-api")
}
