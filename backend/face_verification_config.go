package main

import "fmt"

// resolveFaceVerificationEnabled resolves whether face verification is enabled
// for this environment and validates the Regula connection settings.
//
// Face verification has exactly two states: disabled — the app is told to skip
// the step (no announcement in /api/start-validation), the capture page is
// off, and issuance never touches Regula — and enabled, which is fail-closed:
// issuance is rejected unless a confirmed liveness transaction matches the
// document portrait. There is deliberately no tolerate-old-apps mode in
// between: app versions that obey the issuer's announcement are released
// before any issuer enforces face verification.
//
// An absent face_verification_enabled preserves the historical semantics —
// regula_face_api_url set means enabled — so existing configs keep their exact
// behaviour on upgrade. Enabled requires both URLs: the internal one for
// matching and the public one for the capture page and the announcement to the
// app. Enabled without the public URL would send apps into the step with
// nowhere to run liveness (a dead end at runtime), so it fails at startup
// instead.
//
// Two methods can back the step, independently of each other: Regula
// (variant A, regula_face_api_url + regula_face_api_public_url) and the
// self-hosted face matcher behind on-device verification (variant B,
// face_matcher_url + face_matcher_threshold). Enabled requires at least one
// of them to be fully configured. A deployment may run variant B with no
// Regula at all.
func resolveFaceVerificationEnabled(config *Config) (bool, error) {
	enabled := config.RegulaFaceApiUrl != "" || config.FaceMatcherUrl != ""
	if config.FaceVerificationEnabled != nil {
		enabled = *config.FaceVerificationEnabled
	}
	if !enabled {
		return false, nil
	}

	regulaConfigured := config.RegulaFaceApiUrl != "" || config.RegulaFaceApiPublicUrl != ""
	matcherConfigured := config.FaceMatcherUrl != ""
	if !regulaConfigured && !matcherConfigured {
		return false, fmt.Errorf("face_verification_enabled requires regula_face_api_url or face_matcher_url")
	}

	if regulaConfigured {
		if config.RegulaFaceApiUrl == "" {
			return false, fmt.Errorf("face_verification_enabled requires regula_face_api_url")
		}
		if config.RegulaFaceApiPublicUrl == "" {
			return false, fmt.Errorf("face verification requires regula_face_api_public_url")
		}
	}

	if matcherConfigured && config.FaceMatcherThreshold <= 0 {
		// No default on purpose: the matcher's similarity scale has to be
		// calibrated per deployment, an unset threshold must not silently
		// accept everything or nothing.
		return false, fmt.Errorf("face_matcher_url requires a positive face_matcher_threshold")
	}
	return true, nil
}

// faceVerificationEnabled reports whether face verification is enabled for
// this environment. The configured clients double as the flag: main() only
// constructs them when resolveFaceVerificationEnabled says so.
func (s *ServerState) faceVerificationEnabled() bool {
	return s.faceVerificationClient != nil || s.faceMatcher != nil
}

// faceVerificationMethods lists the methods this issuer accepts evidence for,
// in the order they are announced to the app.
func (s *ServerState) faceVerificationMethods() []string {
	methods := []string{}
	if s.faceVerificationClient != nil {
		methods = append(methods, FaceVerificationMethodRegula)
	}
	if s.faceMatcher != nil {
		methods = append(methods, FaceVerificationMethodIris)
	}
	return methods
}
