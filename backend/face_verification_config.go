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
func resolveFaceVerificationEnabled(config *Config) (bool, error) {
	enabled := config.RegulaFaceApiUrl != ""
	if config.FaceVerificationEnabled != nil {
		enabled = *config.FaceVerificationEnabled
	}
	if !enabled {
		return false, nil
	}

	if config.RegulaFaceApiUrl == "" {
		return false, fmt.Errorf("face_verification_enabled requires regula_face_api_url")
	}
	if config.RegulaFaceApiPublicUrl == "" {
		return false, fmt.Errorf("face verification requires regula_face_api_public_url")
	}
	return true, nil
}

// faceVerificationEnabled reports whether face verification is enabled for
// this environment. The configured Regula client doubles as the flag: main()
// only constructs one when resolveFaceVerificationEnabled says so.
func (s *ServerState) faceVerificationEnabled() bool {
	return s.faceVerificationClient != nil
}
