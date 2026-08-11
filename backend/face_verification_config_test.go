package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func boolPtr(v bool) *bool { return &v }

// Explicit values are honoured (given valid connection settings).
func TestResolveFaceVerification_ExplicitValues(t *testing.T) {
	enabled, err := resolveFaceVerificationEnabled(&Config{
		FaceVerificationEnabled: boolPtr(true),
		RegulaFaceApiUrl:        "http://regula-face-api:41101",
		RegulaFaceApiPublicUrl:  "https://faceapi.example",
	})
	require.NoError(t, err)
	require.True(t, enabled)

	// Explicit false disables even with the URLs still configured, so an
	// environment can be switched off without ripping out its connection
	// settings.
	enabled, err = resolveFaceVerificationEnabled(&Config{
		FaceVerificationEnabled: boolPtr(false),
		RegulaFaceApiUrl:        "http://regula-face-api:41101",
		RegulaFaceApiPublicUrl:  "https://faceapi.example",
	})
	require.NoError(t, err)
	require.False(t, enabled)
}

// An absent key preserves the historical semantics exactly, so a new binary
// with an old config changes nothing.
func TestResolveFaceVerification_AbsentKeyDerivesFromUrl(t *testing.T) {
	enabled, err := resolveFaceVerificationEnabled(&Config{
		RegulaFaceApiUrl:       "http://regula-face-api:41101",
		RegulaFaceApiPublicUrl: "https://faceapi.example",
	})
	require.NoError(t, err)
	require.True(t, enabled, "url set must stay enabled (fail-closed)")

	enabled, err = resolveFaceVerificationEnabled(&Config{})
	require.NoError(t, err)
	require.False(t, enabled, "no url must stay disabled")
}

// Enabled face verification needs both the internal URL (matching) and the
// public one (capture page + announcement to the app); enabled without the
// public URL would send apps into a step with nowhere to run liveness.
func TestResolveFaceVerification_EnabledRequiresBothUrls(t *testing.T) {
	_, err := resolveFaceVerificationEnabled(&Config{
		FaceVerificationEnabled: boolPtr(true),
		RegulaFaceApiPublicUrl:  "https://faceapi.example",
	})
	require.ErrorContains(t, err, "regula_face_api_url")

	_, err = resolveFaceVerificationEnabled(&Config{
		FaceVerificationEnabled: boolPtr(true),
		RegulaFaceApiUrl:        "http://regula-face-api:41101",
	})
	require.ErrorContains(t, err, "regula_face_api_public_url")

	// The absent-key derivation can also land on enabled and must then pass
	// the same validation.
	_, err = resolveFaceVerificationEnabled(&Config{
		RegulaFaceApiUrl: "http://regula-face-api:41101",
	})
	require.ErrorContains(t, err, "regula_face_api_public_url")
}

// The configured client doubles as the runtime flag.
func TestFaceVerificationEnabled_FollowsClientPresence(t *testing.T) {
	require.False(t, (&ServerState{}).faceVerificationEnabled())
	require.True(t,
		(&ServerState{faceVerificationClient: &fakeFaceClient{}}).faceVerificationEnabled())
}
