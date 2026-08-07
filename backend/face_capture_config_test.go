package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestFaceCaptureConfigServesPublicFaceApiUrl verifies the /capture page is told
// the browser-reachable Face API origin, not the internal one the backend uses.
func TestFaceCaptureConfigServesPublicFaceApiUrl(t *testing.T) {
	state := &ServerState{
		// What the backend itself talks to, over the internal network.
		faceVerificationClient: NewRegulaFaceClient("http://regula-face-api:41101", 0),
		// What the browser must use.
		regulaFaceApiPublicUrl: "https://faceapi.staging.yivi.app",
	}

	rec := httptest.NewRecorder()
	handleFaceCaptureConfig(state, rec, httptest.NewRequest(http.MethodGet, "/api/face-capture-config", nil))

	require.Equal(t, http.StatusOK, rec.Code)

	var response FaceCaptureConfigResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	require.Equal(t, "https://faceapi.staging.yivi.app", response.FaceApiUrl)
	// The internal address must never be handed to a browser.
	require.NotContains(t, rec.Body.String(), "regula-face-api")
}

// TestFaceCaptureConfigNotFoundWhenUnconfigured verifies an environment without
// the capture page deployed says so, rather than handing the page an empty URL
// that the Regula component would silently replace with its own cloud default.
func TestFaceCaptureConfigNotFoundWhenUnconfigured(t *testing.T) {
	rec := httptest.NewRecorder()
	handleFaceCaptureConfig(&ServerState{}, rec, httptest.NewRequest(http.MethodGet, "/api/face-capture-config", nil))

	require.Equal(t, http.StatusNotFound, rec.Code)
}

// TestFaceCaptureConfigNotFoundWhenPolicyDisabled verifies a disabled policy
// 404s the capture page even with the public URL still configured, so the page
// and the policy cannot disagree: no liveness session gets captured that
// issuance will never consume.
func TestFaceCaptureConfigNotFoundWhenPolicyDisabled(t *testing.T) {
	state := &ServerState{
		faceVerificationPolicy: FaceVerificationDisabled,
		regulaFaceApiPublicUrl: "https://faceapi.staging.yivi.app",
	}

	rec := httptest.NewRecorder()
	handleFaceCaptureConfig(state, rec, httptest.NewRequest(http.MethodGet, "/api/face-capture-config", nil))

	require.Equal(t, http.StatusNotFound, rec.Code)
}

// TestFaceCaptureConfigRouteIsGetOnly verifies the route is registered and only
// answers GET.
func TestFaceCaptureConfigRouteIsGetOnly(t *testing.T) {
	srv, err := NewServer(&ServerState{
		faceVerificationPolicy: FaceVerificationRequired,
		regulaFaceApiPublicUrl: "https://faceapi.example",
	}, ServerConfig{})
	require.NoError(t, err)

	get := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/api/face-capture-config", nil))
	require.Equal(t, http.StatusOK, get.Code)
	require.Contains(t, get.Body.String(), "faceapi.example")

	// A non-GET request falls through to the SPA handler rather than returning
	// 405 (every route in this router behaves that way), so what matters is that
	// it is not answered with the config.
	post := httptest.NewRecorder()
	srv.server.Handler.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/api/face-capture-config", nil))
	require.NotContains(t, post.Body.String(), "faceapi.example")
}
