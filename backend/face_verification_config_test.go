package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func boolPtr(v bool) *bool { return &v }

// Explicit values are honoured (given a complete block for the method).
func TestResolveFaceVerification_ExplicitValues(t *testing.T) {
	enabled, err := resolveFaceVerificationEnabled(&Config{
		FaceVerificationEnabled: boolPtr(true),
		Regula:                  validRegula(),
	})
	require.NoError(t, err)
	require.True(t, enabled)

	// Explicit false disables even with the block still configured, so an
	// environment can be switched off without ripping out its connection
	// settings.
	enabled, err = resolveFaceVerificationEnabled(&Config{
		FaceVerificationEnabled: boolPtr(false),
		Regula:                  validRegula(),
	})
	require.NoError(t, err)
	require.False(t, enabled)
}

// There is nothing left to derive the flag from now that the connection
// settings live in their own blocks, so an absent key means disabled. A config
// that still carries the old flat keys is refused outright (see
// TestCheckMovedFaceKeys), so no issuer can lose the step silently this way.
func TestResolveFaceVerification_AbsentKeyIsDisabled(t *testing.T) {
	enabled, err := resolveFaceVerificationEnabled(&Config{Regula: validRegula()})
	require.NoError(t, err)
	require.False(t, enabled)

	enabled, err = resolveFaceVerificationEnabled(&Config{})
	require.NoError(t, err)
	require.False(t, enabled)
}

// Enabled face verification needs every enabled method to be possible: the
// block present, with the internal URL (matching), the public one (capture
// page + announcement to the app) and a threshold.
func TestResolveFaceVerification_EnabledRequiresACompleteBlock(t *testing.T) {
	_, err := resolveFaceVerificationEnabled(&Config{FaceVerificationEnabled: boolPtr(true)})
	require.ErrorContains(t, err, "requires a regula config block")

	cfg := validRegula()
	cfg.FaceApiPublicUrl = ""
	_, err = resolveFaceVerificationEnabled(&Config{
		FaceVerificationEnabled: boolPtr(true),
		Regula:                  cfg,
	})
	require.ErrorContains(t, err, "regula.face_api_public_url is required")

	cfg = validRegula()
	cfg.FaceMatchThreshold = 0
	_, err = resolveFaceVerificationEnabled(&Config{
		FaceVerificationEnabled: boolPtr(true),
		Regula:                  cfg,
	})
	require.ErrorContains(t, err, "regula.face_match_threshold is required")
}

// A block that is present is checked whether or not its method is enabled, and
// whether or not face verification is on: half-filled settings are a
// misconfiguration worth reporting before someone switches them on.
func TestResolveFaceVerification_IncompleteBlockFailsEvenWhenOff(t *testing.T) {
	iris := validIris()
	iris.VerifierPublicUrl = ""
	_, err := resolveFaceVerificationEnabled(&Config{
		FaceVerificationEnabled: boolPtr(false),
		Regula:                  validRegula(),
		Iris:                    iris,
	})
	require.ErrorContains(t, err, "iris.verifier_public_url is required")
}

// Thresholds sit on (0, 1] on both scales; the number decides who gets a
// credential, so it is never inherited from a default.
func TestValidateThreshold(t *testing.T) {
	require.ErrorContains(t, validateThreshold("k", 0), "k is required")
	require.ErrorContains(t, validateThreshold("k", -0.1), "k must be in (0, 1]")
	require.ErrorContains(t, validateThreshold("k", 1.01), "k must be in (0, 1]")
	require.NoError(t, validateThreshold("k", 1))
	require.NoError(t, validateThreshold("k", 0.5))
}

// The flat keys that became the blocks are refused by name: ignoring one would
// quietly turn face verification off for an issuer that had it on.
func TestCheckMovedFaceKeys(t *testing.T) {
	err := checkMovedFaceKeys([]byte(`{"irma_server_url":"x","regula_face_api_url":"http://regula:41101"}`))
	require.ErrorContains(t, err, "regula_face_api_url is now regula.face_api_url")

	err = checkMovedFaceKeys([]byte(`{"iris_verifier_url":"x","iris_face_match_threshold":0.75}`))
	require.ErrorContains(t, err, "iris_face_match_threshold is now iris.face_match_threshold")
	require.ErrorContains(t, err, "iris_verifier_url is now iris.verifier_url")

	require.NoError(t, checkMovedFaceKeys([]byte(`{"regula":{"face_api_url":"http://regula:41101"}}`)))
}

// The configured client doubles as the runtime flag.
func TestFaceVerificationEnabled_FollowsClientPresence(t *testing.T) {
	require.False(t, (&ServerState{}).faceVerificationEnabled())
	require.True(t,
		(&ServerState{faceVerificationClient: &fakeFaceClient{}}).faceVerificationEnabled())
}
