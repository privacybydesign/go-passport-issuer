package main

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
// behaviour on upgrade. Enabled requires the connection settings of every
// enabled method (see resolveFaceMethods): for Regula both URLs, the internal
// one for matching and the public one for the capture page and the
// announcement to the app. Enabled without them would send apps into the step
// with nowhere to run it (a dead end at runtime), so it fails at startup
// instead.
func resolveFaceVerificationEnabled(config *Config) (bool, error) {
	enabled := config.RegulaFaceApiUrl != ""
	if config.FaceVerificationEnabled != nil {
		enabled = *config.FaceVerificationEnabled
	}
	if !enabled {
		return false, nil
	}
	if _, err := resolveFaceMethods(config); err != nil {
		return false, err
	}
	return true, nil
}

// faceVerificationEnabled reports whether face verification is enabled for
// this environment: whether any method may be assigned. Without an explicit
// method policy, the configured Regula client doubles as the flag, as it did
// before methods existed.
func (s *ServerState) faceVerificationEnabled() bool {
	return s.methodPolicy().Enabled()
}
