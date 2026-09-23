package main

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// RegulaConfig holds everything the Regula method needs, scoped to that method
// so a reader can see at a glance what enabling it costs. Every field is
// required: a present block must be complete, and the method cannot be enabled
// without the block (see resolveFaceMethods).
type RegulaConfig struct {
	// Cluster-internal base URL of the Regula Face API, e.g.
	// http://regula-face-api:41101. The backend matches and confirms liveness
	// over this one.
	FaceApiUrl string `json:"face_api_url"`
	// Browser-reachable origin of the same service, served to the /capture
	// liveness page and announced to the app in /api/start-validation.
	// Distinct from FaceApiUrl, which a browser generally cannot resolve.
	FaceApiPublicUrl string `json:"face_api_public_url"`
	// Similarity in (0, 1] at or above which the live face is a match for the
	// document portrait. Higher is stricter.
	FaceMatchThreshold float64 `json:"face_match_threshold"`
}

// IrisConfig holds everything the Iris method needs. Like RegulaConfig, every
// field is required.
type IrisConfig struct {
	// Cluster-internal base URL of the Iris verifier, e.g.
	// http://iris-verifier-svc:8081. The issuer opens and reads face sessions
	// over this one.
	VerifierUrl string `json:"verifier_url"`
	// Wallet-reachable origin of the verifier's stream endpoint, e.g.
	// wss://iris-verifier.staging.yivi.app, from which each session's stream
	// URL is built.
	VerifierPublicUrl string `json:"verifier_public_url"`
	// Distance in (0, 1] at or below which the live face is a match for the
	// document portrait. The counterpart of
	// RegulaConfig.FaceMatchThreshold on the other method's scale, where lower
	// is stricter. The verifier applies a threshold of its own to the verdict
	// it shows the wallet; this one decides issuance.
	FaceMatchThreshold float64 `json:"face_match_threshold"`
}

// validate reports whether the block is usable. A nil block is not an error
// here — a method that is switched off needs no settings — but a block that is
// present must be complete, because a half-filled one is a misconfiguration
// rather than a partial opt-in.
func (c *RegulaConfig) validate() error {
	if c == nil {
		return nil
	}
	if c.FaceApiUrl == "" {
		return fmt.Errorf("regula.face_api_url is required")
	}
	if c.FaceApiPublicUrl == "" {
		return fmt.Errorf("regula.face_api_public_url is required")
	}
	return validateThreshold("regula.face_match_threshold", c.FaceMatchThreshold)
}

// validate is RegulaConfig.validate for the Iris block.
func (c *IrisConfig) validate() error {
	if c == nil {
		return nil
	}
	if c.VerifierUrl == "" {
		return fmt.Errorf("iris.verifier_url is required")
	}
	if c.VerifierPublicUrl == "" {
		return fmt.Errorf("iris.verifier_public_url is required")
	}
	return validateThreshold("iris.face_match_threshold", c.FaceMatchThreshold)
}

// validateThreshold rejects an absent or out-of-range threshold. There is no
// default: how strict face verification is decides who gets a credential, so
// every environment states it rather than inheriting a number from a release.
// Zero is what an absent key decodes to, and it is meaningless on both scales
// (a similarity floor of 0 matches everything, a distance ceiling of 0 matches
// nothing), so it is reported as missing.
func validateThreshold(key string, threshold float64) error {
	if threshold == 0 {
		return fmt.Errorf("%s is required", key)
	}
	if threshold < 0 || threshold > 1 {
		return fmt.Errorf("%s must be in (0, 1], got %v", key, threshold)
	}
	return nil
}

// movedFaceKeys are the flat config keys that became the regula and iris
// blocks. A config still carrying one would have it silently ignored, which
// for an issuer that had face verification on means the step quietly stops
// happening, so startup fails and names the replacement instead.
var movedFaceKeys = map[string]string{
	"regula_face_api_url":         "regula.face_api_url",
	"regula_face_api_public_url":  "regula.face_api_public_url",
	"regula_face_match_threshold": "regula.face_match_threshold",
	"iris_verifier_url":           "iris.verifier_url",
	"iris_verifier_public_url":    "iris.verifier_public_url",
	"iris_face_match_threshold":   "iris.face_match_threshold",
}

// checkMovedFaceKeys fails on a config that still uses the flat keys.
func checkMovedFaceKeys(configBytes []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(configBytes, &raw); err != nil {
		return err
	}
	var moved []string
	for key, now := range movedFaceKeys {
		if _, ok := raw[key]; ok {
			moved = append(moved, key+" is now "+now)
		}
	}
	if len(moved) == 0 {
		return nil
	}
	slices.Sort(moved)
	return fmt.Errorf("face verification settings moved into the regula and iris blocks: %s", strings.Join(moved, "; "))
}

// resolveFaceVerificationEnabled resolves whether face verification is enabled
// for this environment and validates the configuration of both methods.
//
// Face verification has exactly two states: disabled — the app is told to skip
// the step (no announcement in /api/start-validation), the capture page is
// off, and issuance never touches a face service — and enabled, which is
// fail-closed: issuance is rejected unless the assigned method verified the
// holder against the document portrait. There is deliberately no
// tolerate-old-apps mode in between: app versions that obey the issuer's
// announcement are released before any issuer enforces face verification.
//
// Enabled requires every enabled method to be possible: its block present and
// complete (see resolveFaceMethods). Enabled without that would send apps into
// a step with nowhere to run it — a dead end at runtime — so it fails at
// startup instead. An absent face_verification_enabled means disabled; there
// is nothing left to derive it from now that the connection settings live in
// their own blocks.
func resolveFaceVerificationEnabled(config *Config) (bool, error) {
	// Checked whether or not the method is enabled: a block someone left
	// half-filled is worth reporting before it is switched on.
	if err := config.Regula.validate(); err != nil {
		return false, err
	}
	if err := config.Iris.validate(); err != nil {
		return false, err
	}

	if config.FaceVerificationEnabled == nil || !*config.FaceVerificationEnabled {
		return false, nil
	}
	if _, err := resolveFaceMethods(config); err != nil {
		return false, err
	}
	return true, nil
}

// faceVerificationEnabled reports whether face verification is enabled for
// this environment: whether any method may be assigned.
func (s *ServerState) faceVerificationEnabled() bool {
	return s.methodPolicy().Enabled()
}
