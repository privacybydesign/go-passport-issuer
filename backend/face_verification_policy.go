package main

import "fmt"

// FaceVerificationPolicy is the issuer's per-environment stance on face
// verification during document issuance:
//
//   - disabled: the step does not apply. The app is told to skip it entirely
//     (no announcement in /api/start-validation), the capture page is off, and
//     issuance never touches the Regula client.
//   - optional: transitional. Apps that can verify must — a provided liveness
//     transaction id is always fully enforced — while old apps that cannot
//     (no id) are tolerated and logged, so the flip to "required" can be timed
//     on real traffic.
//   - required: no verified face, no credential. Issuance without a liveness
//     transaction id is rejected.
type FaceVerificationPolicy string

const (
	FaceVerificationDisabled FaceVerificationPolicy = "disabled"
	FaceVerificationOptional FaceVerificationPolicy = "optional"
	FaceVerificationRequired FaceVerificationPolicy = "required"
)

// resolveFaceVerificationPolicy resolves the configured policy and validates
// it against the Regula connection settings.
//
// An absent key preserves the pre-policy semantics exactly, so deploying a new
// binary with an old config changes nothing: regula_face_api_url set means
// "required" (fail-closed), unset means "disabled". "optional" is always an
// explicit opt-in.
//
// A non-disabled policy needs both URLs: the internal one for matching and the
// public one for the capture page and the announcement to the app.
func resolveFaceVerificationPolicy(config *Config) (FaceVerificationPolicy, error) {
	var policy FaceVerificationPolicy
	switch FaceVerificationPolicy(config.FaceVerificationPolicy) {
	case FaceVerificationDisabled, FaceVerificationOptional, FaceVerificationRequired:
		policy = FaceVerificationPolicy(config.FaceVerificationPolicy)
	case "":
		if config.RegulaFaceApiUrl != "" {
			policy = FaceVerificationRequired
		} else {
			policy = FaceVerificationDisabled
		}
	default:
		return "", fmt.Errorf(
			"invalid face_verification_policy %q: must be %q, %q or %q",
			config.FaceVerificationPolicy,
			FaceVerificationDisabled, FaceVerificationOptional, FaceVerificationRequired,
		)
	}

	if policy != FaceVerificationDisabled {
		if config.RegulaFaceApiUrl == "" {
			return "", fmt.Errorf(
				"face_verification_policy %q requires regula_face_api_url", policy,
			)
		}
		if config.RegulaFaceApiPublicUrl == "" {
			return "", fmt.Errorf(
				"face_verification_policy %q requires regula_face_api_public_url", policy,
			)
		}
	}

	return policy, nil
}

// facePolicy returns the resolved policy, normalizing the zero value so a
// ServerState constructed without one (tests, future call sites) keeps the
// pre-policy fail-closed semantics: a configured client means "required",
// no client means "disabled". main() always sets an explicitly resolved policy.
func (s *ServerState) facePolicy() FaceVerificationPolicy {
	if s.faceVerificationPolicy != "" {
		return s.faceVerificationPolicy
	}
	if s.faceVerificationClient != nil {
		return FaceVerificationRequired
	}
	return FaceVerificationDisabled
}
