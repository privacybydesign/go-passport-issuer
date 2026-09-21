package main

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"

	"go-passport-issuer/analytics"
)

// FaceMethod is a face verification method as named on the wire. The
// recorder package owns the names so the issuer and the Iris verifier record
// the same strings.
type FaceMethod = analytics.Method

const (
	FaceMethodRegula = analytics.MethodRegula
	FaceMethodIris   = analytics.MethodIris
)

// FaceMethodConfig is one method's entry in `face_verification_methods`.
type FaceMethodConfig struct {
	Enabled bool `json:"enabled"`
	// Weight in the random draw when several methods are candidates for a
	// session. Zero keeps an enabled method out of the draw while still
	// letting it be assigned when it is the only candidate or a sticky retry.
	Weight int `json:"weight"`
}

// FaceMethodsConfig is the `face_verification_methods` block of config.json.
type FaceMethodsConfig struct {
	Regula FaceMethodConfig `json:"regula"`
	Iris   FaceMethodConfig `json:"iris"`
}

// defaultFaceMethods is what an enabled issuer without a
// `face_verification_methods` block means: exactly today's behaviour.
var defaultFaceMethods = FaceMethodsConfig{
	Regula: FaceMethodConfig{Enabled: true, Weight: 1},
}

// FaceVerificationDeclaration is the `face_verification` block a wallet may
// send with /api/start-validation: what it can run and, on a retry, what it
// was assigned before. Wallets released before the block existed send nothing.
type FaceVerificationDeclaration struct {
	// Wire names of the methods this build can run. Absent or empty means
	// ["regula"], the only method those wallets support. Unknown names are
	// ignored.
	Capabilities []string `json:"capabilities"`
	// Set on a retry within one document flow: the method assigned last time.
	PreviousMethod string `json:"previous_method,omitempty"`
	// Set on a retry: the number of this attempt, starting at 2.
	Attempt int `json:"attempt,omitempty"`
	// A tester's preference, honoured only when allow_client_preference is on.
	PreferredMethod string `json:"preferred_method,omitempty"`
}

// StartValidationRequest is the optional body of /api/start-validation.
type StartValidationRequest struct {
	FaceVerification *FaceVerificationDeclaration `json:"face_verification,omitempty"`
	// Coarse labels of the wallet build, for the recordings only.
	Client *analytics.Client `json:"client,omitempty"`
}

// ErrNoCandidateMethod: the wallet declared nothing this issuer has enabled.
// Only possible when Regula is disabled while Regula-only wallets exist.
var ErrNoCandidateMethod = errors.New("no enabled face verification method among the wallet's capabilities")

// FaceMethodPolicy assigns a method to a session from what the wallet declared
// and what the issuer has enabled. The zero value is "not configured": see
// ServerState.methodPolicy for how that is resolved.
type FaceMethodPolicy struct {
	methods               map[FaceMethod]FaceMethodConfig
	allowClientPreference bool
	// intn draws the weighted random choice; injectable for tests.
	intn func(n int) int
}

// NewFaceMethodPolicy builds the policy from config. Disabled methods are kept
// in the map so IsEnabled can answer for every known method.
func NewFaceMethodPolicy(cfg FaceMethodsConfig, allowClientPreference bool) FaceMethodPolicy {
	return FaceMethodPolicy{
		methods: map[FaceMethod]FaceMethodConfig{
			FaceMethodRegula: cfg.Regula,
			FaceMethodIris:   cfg.Iris,
		},
		allowClientPreference: allowClientPreference,
		intn:                  rand.IntN,
	}
}

// regulaOnlyPolicy is the policy for a ServerState that was given a Regula
// client but no explicit method configuration: the behaviour before methods
// existed.
func regulaOnlyPolicy(enabled bool) FaceMethodPolicy {
	return NewFaceMethodPolicy(FaceMethodsConfig{
		Regula: FaceMethodConfig{Enabled: enabled, Weight: 1},
	}, false)
}

func (p FaceMethodPolicy) configured() bool { return p.methods != nil }

// Enabled reports whether any method is enabled, i.e. whether the face
// verification step applies in this environment at all.
func (p FaceMethodPolicy) Enabled() bool {
	for _, m := range p.methods {
		if m.Enabled {
			return true
		}
	}
	return false
}

// IsEnabled reports whether one method may be assigned.
func (p FaceMethodPolicy) IsEnabled(method FaceMethod) bool {
	return p.methods[method].Enabled
}

// AllowsClientPreference reports whether preferred_method is honoured.
func (p FaceMethodPolicy) AllowsClientPreference() bool { return p.allowClientPreference }

// parseFaceMethod returns the method for a wire name, or "" for an unknown one.
func parseFaceMethod(wireName string) FaceMethod {
	switch FaceMethod(wireName) {
	case FaceMethodRegula, FaceMethodIris:
		return FaceMethod(wireName)
	}
	return ""
}

// declaredCapabilities turns the wallet's declaration into known methods in
// declared order, without duplicates. No declaration, or an empty list, means
// Regula: wallets from before the declaration existed can run exactly that.
// A non-empty list of only unknown names stays empty: such a wallet cannot run
// Regula either, and saying so (a 400) beats sending it into a step it fails.
func declaredCapabilities(decl *FaceVerificationDeclaration) []FaceMethod {
	if decl == nil || len(decl.Capabilities) == 0 {
		return []FaceMethod{FaceMethodRegula}
	}
	var out []FaceMethod
	seen := map[FaceMethod]bool{}
	for _, name := range decl.Capabilities {
		m := parseFaceMethod(name)
		if m == "" || seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	return out
}

// Assign picks the method for one session. Rules, in order:
//
//  1. candidates = declared capabilities ∩ enabled methods;
//  2. none → ErrNoCandidateMethod;
//  3. preferred_method among the candidates, and the issuer allows client
//     preference → that;
//  4. previous_method among the candidates → that (sticky retry);
//  5. one candidate → that, regardless of weight;
//  6. several → weighted random draw; weight 0 stays out of the draw.
func (p FaceMethodPolicy) Assign(decl *FaceVerificationDeclaration) (FaceMethod, error) {
	var candidates []FaceMethod
	for _, m := range declaredCapabilities(decl) {
		if p.IsEnabled(m) {
			candidates = append(candidates, m)
		}
	}
	if len(candidates) == 0 {
		return "", ErrNoCandidateMethod
	}

	if decl != nil {
		if p.allowClientPreference {
			if m := parseFaceMethod(decl.PreferredMethod); m != "" && slices.Contains(candidates, m) {
				return m, nil
			}
		}
		if m := parseFaceMethod(decl.PreviousMethod); m != "" && slices.Contains(candidates, m) {
			return m, nil
		}
	}

	if len(candidates) == 1 {
		return candidates[0], nil
	}

	total := 0
	for _, m := range candidates {
		if w := p.methods[m].Weight; w > 0 {
			total += w
		}
	}
	if total == 0 {
		// Every candidate is weighted out of the draw; there is still a step to
		// run, so fall back to the first declared candidate rather than fail.
		return candidates[0], nil
	}
	draw := p.intn(total)
	for _, m := range candidates {
		w := p.methods[m].Weight
		if w <= 0 {
			continue
		}
		if draw < w {
			return m, nil
		}
		draw -= w
	}
	return candidates[len(candidates)-1], nil
}

// resolveFaceMethods validates the method configuration for an environment in
// which face verification is enabled and returns the effective configuration.
// An absent block means Regula only, as before methods existed. Each enabled
// method needs its connection settings: Regula the two Face API URLs (as
// before), Iris the two verifier URLs. Enabled face verification without a
// single enabled method is a configuration error, not a way to disable it.
func resolveFaceMethods(config *Config) (FaceMethodsConfig, error) {
	methods := defaultFaceMethods
	if config.FaceVerificationMethods != nil {
		methods = *config.FaceVerificationMethods
	}
	if !methods.Regula.Enabled && !methods.Iris.Enabled {
		return methods, fmt.Errorf("face_verification_enabled requires at least one enabled method in face_verification_methods")
	}
	if methods.Regula.Weight < 0 || methods.Iris.Weight < 0 {
		return methods, fmt.Errorf("face_verification_methods weights must not be negative")
	}
	if methods.Regula.Enabled {
		if config.RegulaFaceApiUrl == "" {
			return methods, fmt.Errorf("face_verification_enabled requires regula_face_api_url")
		}
		if config.RegulaFaceApiPublicUrl == "" {
			return methods, fmt.Errorf("face verification requires regula_face_api_public_url")
		}
	}
	if methods.Iris.Enabled {
		if config.IrisVerifierUrl == "" {
			return methods, fmt.Errorf("face_verification_methods.iris.enabled requires iris_verifier_url")
		}
		if config.IrisVerifierPublicUrl == "" {
			return methods, fmt.Errorf("face_verification_methods.iris.enabled requires iris_verifier_public_url")
		}
	}
	return methods, nil
}
