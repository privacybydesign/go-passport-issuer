package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Explicit values resolve as themselves (given valid connection settings).
func TestResolvePolicy_ExplicitValues(t *testing.T) {
	for _, policy := range []FaceVerificationPolicy{
		FaceVerificationOptional, FaceVerificationRequired,
	} {
		resolved, err := resolveFaceVerificationPolicy(&Config{
			FaceVerificationPolicy: string(policy),
			RegulaFaceApiUrl:       "http://regula-face-api:41101",
			RegulaFaceApiPublicUrl: "https://faceapi.example",
		})
		require.NoError(t, err, policy)
		require.Equal(t, policy, resolved)
	}

	// disabled needs no URLs at all.
	resolved, err := resolveFaceVerificationPolicy(&Config{
		FaceVerificationPolicy: "disabled",
	})
	require.NoError(t, err)
	require.Equal(t, FaceVerificationDisabled, resolved)
}

// An absent key preserves the pre-policy semantics exactly, so a new binary
// with an old config changes nothing.
func TestResolvePolicy_AbsentKeyDerivesFromUrl(t *testing.T) {
	resolved, err := resolveFaceVerificationPolicy(&Config{
		RegulaFaceApiUrl:       "http://regula-face-api:41101",
		RegulaFaceApiPublicUrl: "https://faceapi.example",
	})
	require.NoError(t, err)
	require.Equal(t, FaceVerificationRequired, resolved, "url set must stay fail-closed")

	resolved, err = resolveFaceVerificationPolicy(&Config{})
	require.NoError(t, err)
	require.Equal(t, FaceVerificationDisabled, resolved, "no url must stay disabled")
}

func TestResolvePolicy_InvalidValueIsFatal(t *testing.T) {
	_, err := resolveFaceVerificationPolicy(&Config{
		FaceVerificationPolicy: "on",
		RegulaFaceApiUrl:       "http://regula-face-api:41101",
		RegulaFaceApiPublicUrl: "https://faceapi.example",
	})
	require.ErrorContains(t, err, "invalid face_verification_policy")
}

// A non-disabled policy needs both the internal URL (matching) and the public
// one (capture page + announcement to the app).
func TestResolvePolicy_EnabledRequiresBothUrls(t *testing.T) {
	_, err := resolveFaceVerificationPolicy(&Config{
		FaceVerificationPolicy: "optional",
		RegulaFaceApiPublicUrl: "https://faceapi.example",
	})
	require.ErrorContains(t, err, "regula_face_api_url")

	_, err = resolveFaceVerificationPolicy(&Config{
		FaceVerificationPolicy: "required",
		RegulaFaceApiUrl:       "http://regula-face-api:41101",
	})
	require.ErrorContains(t, err, "regula_face_api_public_url")

	// The absent-key derivation can also land on required and must then pass
	// the same validation.
	_, err = resolveFaceVerificationPolicy(&Config{
		RegulaFaceApiUrl: "http://regula-face-api:41101",
	})
	require.ErrorContains(t, err, "regula_face_api_public_url")
}

// The zero value on ServerState normalizes to the pre-policy fail-closed
// semantics, so states constructed without a policy keep their old meaning.
func TestFacePolicy_ZeroValueNormalization(t *testing.T) {
	require.Equal(t, FaceVerificationDisabled, (&ServerState{}).facePolicy())
	require.Equal(t, FaceVerificationRequired,
		(&ServerState{faceVerificationClient: &fakeFaceClient{}}).facePolicy())
	require.Equal(t, FaceVerificationOptional,
		(&ServerState{faceVerificationPolicy: FaceVerificationOptional}).facePolicy())
}
