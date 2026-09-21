package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func policy(regula, iris FaceMethodConfig, allowPreference bool, draws ...int) FaceMethodPolicy {
	p := NewFaceMethodPolicy(FaceMethodsConfig{Regula: regula, Iris: iris}, allowPreference)
	// Deterministic draw sequence for the weighted tests; the last value
	// repeats once the sequence is exhausted.
	if len(draws) > 0 {
		i := 0
		p.intn = func(n int) int {
			d := draws[min(i, len(draws)-1)]
			i++
			return d % n
		}
	}
	return p
}

var (
	on      = FaceMethodConfig{Enabled: true, Weight: 50}
	off     = FaceMethodConfig{Enabled: false, Weight: 50}
	onZero  = FaceMethodConfig{Enabled: true, Weight: 0}
	both    = &FaceVerificationDeclaration{Capabilities: []string{"regula", "iris"}}
	irisDec = &FaceVerificationDeclaration{Capabilities: []string{"iris"}}
)

// Every rule of the assignment, in order, plus the old-wallet default and the
// empty candidate set.
func TestAssign(t *testing.T) {
	tests := []struct {
		name   string
		policy FaceMethodPolicy
		decl   *FaceVerificationDeclaration
		want   FaceMethod
		err    error
	}{
		// Old wallet: no declaration at all → Regula, the only thing it can do.
		{"no declaration is regula", policy(on, on, false), nil, FaceMethodRegula, nil},
		{"empty capabilities is regula", policy(on, on, false), &FaceVerificationDeclaration{}, FaceMethodRegula, nil},
		// Rule 1+2: declared ∩ enabled.
		{"declared iris, iris disabled → none", policy(on, off, false), irisDec, "", ErrNoCandidateMethod},
		{"old wallet, regula disabled → none", policy(off, on, false), nil, "", ErrNoCandidateMethod},
		{"only unknown names → none", policy(on, on, false), &FaceVerificationDeclaration{Capabilities: []string{"holo"}}, "", ErrNoCandidateMethod},
		{"unknown names are ignored beside known ones", policy(on, on, false), &FaceVerificationDeclaration{Capabilities: []string{"holo", "iris"}}, FaceMethodIris, nil},
		// Rule 3: preference only when allowed and a candidate.
		{"preference honoured when allowed", policy(on, on, true), &FaceVerificationDeclaration{Capabilities: both.Capabilities, PreferredMethod: "iris"}, FaceMethodIris, nil},
		{"preference ignored when not allowed", policy(on, on, false, 0), &FaceVerificationDeclaration{Capabilities: both.Capabilities, PreferredMethod: "iris"}, FaceMethodRegula, nil},
		{"preference for a disabled method is ignored", policy(on, off, true), &FaceVerificationDeclaration{Capabilities: both.Capabilities, PreferredMethod: "iris"}, FaceMethodRegula, nil},
		{"preference beats sticky retry", policy(on, on, true), &FaceVerificationDeclaration{Capabilities: both.Capabilities, PreferredMethod: "regula", PreviousMethod: "iris", Attempt: 2}, FaceMethodRegula, nil},
		// Rule 4: sticky retry.
		{"previous method kept while a candidate", policy(on, on, false, 0), &FaceVerificationDeclaration{Capabilities: both.Capabilities, PreviousMethod: "iris", Attempt: 2}, FaceMethodIris, nil},
		{"previous method dropped once disabled", policy(on, off, false), &FaceVerificationDeclaration{Capabilities: both.Capabilities, PreviousMethod: "iris", Attempt: 2}, FaceMethodRegula, nil},
		{"previous method kept even at weight zero", policy(on, onZero, false, 0), &FaceVerificationDeclaration{Capabilities: both.Capabilities, PreviousMethod: "iris", Attempt: 2}, FaceMethodIris, nil},
		// Rule 5: a single candidate wins regardless of weight.
		{"single candidate at weight zero", policy(onZero, off, false), nil, FaceMethodRegula, nil},
		{"single candidate iris", policy(off, on, false), both, FaceMethodIris, nil},
		// Rule 6: weighted draw.
		{"draw lands on regula", policy(on, on, false, 49), both, FaceMethodRegula, nil},
		{"draw lands on iris", policy(on, on, false, 50), both, FaceMethodIris, nil},
		{"weight zero is out of the draw", policy(on, onZero, false, 0, 49), both, FaceMethodRegula, nil},
		{"all weights zero falls back to the first declared", policy(onZero, onZero, false), &FaceVerificationDeclaration{Capabilities: []string{"iris", "regula"}}, FaceMethodIris, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.policy.Assign(tt.decl)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// The draw follows the weights: with 10/90 about a tenth lands on Regula.
func TestAssignWeightedDrawDistribution(t *testing.T) {
	p := NewFaceMethodPolicy(FaceMethodsConfig{
		Regula: FaceMethodConfig{Enabled: true, Weight: 10},
		Iris:   FaceMethodConfig{Enabled: true, Weight: 90},
	}, false)
	regula := 0
	const n = 5000
	for i := 0; i < n; i++ {
		m, err := p.Assign(both)
		require.NoError(t, err)
		if m == FaceMethodRegula {
			regula++
		}
	}
	require.InDelta(t, 0.10, float64(regula)/n, 0.03)
}

func TestPolicyEnabledAndConfigured(t *testing.T) {
	require.False(t, FaceMethodPolicy{}.configured())
	require.False(t, FaceMethodPolicy{}.Enabled())
	require.True(t, policy(off, off, false).configured())
	require.False(t, policy(off, off, false).Enabled())
	require.True(t, policy(off, on, false).Enabled())
	require.True(t, policy(off, on, false).IsEnabled(FaceMethodIris))
	require.False(t, policy(off, on, false).IsEnabled(FaceMethodRegula))
}

// Without an explicit policy, a Regula client stands for Regula-only, so
// server state built the old way (and the existing tests) keeps its meaning.
func TestMethodPolicyDefaultsToRegulaWhenClientPresent(t *testing.T) {
	withClient := &ServerState{faceVerificationClient: &fakeFaceClient{}}
	require.True(t, withClient.faceVerificationEnabled())
	m, err := withClient.methodPolicy().Assign(nil)
	require.NoError(t, err)
	require.Equal(t, FaceMethodRegula, m)
	_, err = withClient.methodPolicy().Assign(irisDec)
	require.ErrorIs(t, err, ErrNoCandidateMethod)

	require.False(t, (&ServerState{}).faceVerificationEnabled())

	// An explicit policy wins over the client's presence.
	irisOnly := &ServerState{faceMethods: policy(off, on, false)}
	require.True(t, irisOnly.faceVerificationEnabled())
	m, err = irisOnly.methodPolicy().Assign(both)
	require.NoError(t, err)
	require.Equal(t, FaceMethodIris, m)
}

// Startup validation of the methods block.
func TestResolveFaceMethods(t *testing.T) {
	regulaUrls := Config{RegulaFaceApiUrl: "http://regula:41101", RegulaFaceApiPublicUrl: "https://faceapi.example"}
	irisUrls := Config{IrisVerifierUrl: "http://iris-verifier-svc:8081", IrisVerifierPublicUrl: "wss://iris-verifier.example"}

	t.Run("absent block means regula only", func(t *testing.T) {
		methods, err := resolveFaceMethods(&regulaUrls)
		require.NoError(t, err)
		require.Equal(t, defaultFaceMethods, methods)
	})
	t.Run("no enabled method is an error", func(t *testing.T) {
		cfg := regulaUrls
		cfg.FaceVerificationMethods = &FaceMethodsConfig{}
		_, err := resolveFaceMethods(&cfg)
		require.ErrorContains(t, err, "at least one enabled method")
	})
	t.Run("regula enabled needs its urls", func(t *testing.T) {
		cfg := Config{FaceVerificationMethods: &FaceMethodsConfig{Regula: on}}
		_, err := resolveFaceMethods(&cfg)
		require.ErrorContains(t, err, "regula_face_api_url")
		cfg.RegulaFaceApiUrl = "http://regula:41101"
		_, err = resolveFaceMethods(&cfg)
		require.ErrorContains(t, err, "regula_face_api_public_url")
	})
	t.Run("iris enabled needs its urls", func(t *testing.T) {
		cfg := Config{FaceVerificationMethods: &FaceMethodsConfig{Iris: on}}
		_, err := resolveFaceMethods(&cfg)
		require.ErrorContains(t, err, "iris_verifier_url")
		cfg.IrisVerifierUrl = "http://iris-verifier-svc:8081"
		_, err = resolveFaceMethods(&cfg)
		require.ErrorContains(t, err, "iris_verifier_public_url")
	})
	t.Run("iris only needs no regula urls", func(t *testing.T) {
		cfg := irisUrls
		cfg.FaceVerificationMethods = &FaceMethodsConfig{Iris: on}
		methods, err := resolveFaceMethods(&cfg)
		require.NoError(t, err)
		require.False(t, methods.Regula.Enabled)
		require.True(t, methods.Iris.Enabled)
		// And face verification as a whole is then enabled.
		enabled, err := resolveFaceVerificationEnabled(&Config{
			FaceVerificationEnabled: boolPtr(true),
			IrisVerifierUrl:         cfg.IrisVerifierUrl,
			IrisVerifierPublicUrl:   cfg.IrisVerifierPublicUrl,
			FaceVerificationMethods: cfg.FaceVerificationMethods,
		})
		require.NoError(t, err)
		require.True(t, enabled)
	})
	t.Run("negative weights are rejected", func(t *testing.T) {
		cfg := regulaUrls
		cfg.FaceVerificationMethods = &FaceMethodsConfig{Regula: FaceMethodConfig{Enabled: true, Weight: -1}}
		_, err := resolveFaceMethods(&cfg)
		require.ErrorContains(t, err, "negative")
	})
}

func TestCreateRecorder(t *testing.T) {
	for _, name := range []string{"", "stderr", "none"} {
		r, err := createRecorder(name)
		require.NoError(t, err, name)
		require.NotNil(t, r, name)
	}
	_, err := createRecorder("prometheus")
	require.Error(t, err)
}
