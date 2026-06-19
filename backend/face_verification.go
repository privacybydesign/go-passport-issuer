package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// FaceSession is the subset of a face verification session that is safe to
// return to the caller (e.g. the wallet). It lets the client connect to the
// live verification stream. The binding_secret returned by the face service is
// deliberately NOT exposed here: it is used to authenticate result callbacks and
// must not leave the issuer.
type FaceSession struct {
	// Identifier used in every subsequent face verification call.
	FaceSessionID string `json:"face_session_id"`
	// Base64url-encoded blob the wallet uses to learn the session id and stream URL.
	FaceSessionToken string `json:"face_session_token,omitempty"`
	// WebSocket endpoint the client streams camera frames to.
	WebsocketURL string `json:"websocket_url,omitempty"`
	// True when a reference portrait was supplied at creation (always true here).
	BindingKeyReady bool `json:"binding_key_ready"`
}

// FaceSessionCreator starts a face verification session bound to a reference
// portrait. It is an interface so the HTTP client can be swapped for a fake in
// tests.
type FaceSessionCreator interface {
	// CreateSession starts a session at the face verification service, passing
	// the reference photo as portraitImage. This must be the original DG2 bytes
	// (base64-encoded), since the binding key is derived from
	// SHA256(reference_photo) and the mobile app derives the same key over the
	// raw DG2 it read from the chip.
	//
	// It returns the public session (safe to hand to the wallet) and the
	// binding_secret. The binding_secret authenticates the result callback and
	// must be persisted server-side; it is never returned to the wallet.
	CreateSession(ctx context.Context, portraitImage string) (session *FaceSession, bindingSecret string, err error)
}

// FaceVerificationResult is the authoritative outcome of a face verification
// session, as learned from the signed callback or the status endpoint.
type FaceVerificationResult struct {
	// "success", "failed", "error", or "pending" when not yet complete.
	Status          string   `json:"status"`
	MatchConfidence *float64 `json:"match_confidence,omitempty"`
	LivenessPassed  *bool    `json:"liveness_passed,omitempty"`
}

// FaceSessionStatusGetter polls the face verification service for the result of
// a session. It is the pull fallback used when the pushed callback has not yet
// arrived by the time issuance is requested.
type FaceSessionStatusGetter interface {
	// GetSessionStatus returns the current result for a face session. Status is
	// "pending" while the session is not yet complete.
	GetSessionStatus(ctx context.Context, faceSessionID string) (*FaceVerificationResult, error)
}

// faceSessionRequest is the body for POST /api/face/session.
type faceSessionRequest struct {
	VerifierID    string `json:"verifier_id"`
	CallbackURL   string `json:"callback_url,omitempty"`
	PortraitImage string `json:"portrait_image"`
}

// faceSessionResponse is the full response from POST /api/face/session. The
// binding_secret is read but never propagated outside the issuer.
type faceSessionResponse struct {
	FaceSessionID    string `json:"face_session_id"`
	FaceSessionToken string `json:"face_session_token"`
	BindingSecret    string `json:"binding_secret"`
	WebsocketURL     string `json:"websocket_url"`
	BindingKeyReady  bool   `json:"binding_key_ready"`
}

// FaceVerificationConfig configures the optional integration with the
// face verification service. When URL is empty the integration is disabled and
// validation behaves exactly as before.
type FaceVerificationConfig struct {
	// Base URL of the face verification service, e.g. https://face.example.com.
	URL string `json:"url"`
	// Identifier of this issuer as known to the face verification service.
	VerifierID string `json:"verifier_id"`
	// Optional URL the face service calls with the signed result.
	CallbackURL string `json:"callback_url,omitempty"`
	// Optional request timeout in seconds (defaults to 10s).
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
	// Whether issuance must be gated on a successful face verification. When nil
	// it defaults to true (gate on) for any configured (URL set) integration;
	// set false to run face verification as advisory only.
	RequireFaceForIssuance *bool `json:"require_face_for_issuance,omitempty"`
}

// FaceVerificationClient talks to the face verification service over HTTP.
type FaceVerificationClient struct {
	baseURL     string
	verifierID  string
	callbackURL string
	httpClient  *http.Client
}

// NewFaceVerificationClient builds a client from config, or returns nil (with no
// error) when the integration is not configured.
func NewFaceVerificationClient(config FaceVerificationConfig) *FaceVerificationClient {
	if strings.TrimSpace(config.URL) == "" {
		return nil
	}

	timeout := 10 * time.Second
	if config.TimeoutSeconds > 0 {
		timeout = time.Duration(config.TimeoutSeconds) * time.Second
	}

	verifierID := config.VerifierID
	if verifierID == "" {
		verifierID = "passport-issuer"
	}

	return &FaceVerificationClient{
		baseURL:     strings.TrimRight(config.URL, "/"),
		verifierID:  verifierID,
		callbackURL: config.CallbackURL,
		httpClient:  &http.Client{Timeout: timeout},
	}
}

// CreateSession implements FaceSessionCreator.
func (c *FaceVerificationClient) CreateSession(ctx context.Context, portraitImage string) (*FaceSession, string, error) {
	if portraitImage == "" {
		return nil, "", fmt.Errorf("portrait image is empty")
	}

	body, err := json.Marshal(faceSessionRequest{
		VerifierID:    c.verifierID,
		CallbackURL:   c.callbackURL,
		PortraitImage: portraitImage,
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal face session request: %w", err)
	}

	endpoint := c.baseURL + "/api/face/session"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("failed to build face session request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to call face verification service: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			slog.Error("failed to close face session response body", "error", cerr)
		}
	}()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, "", fmt.Errorf("failed to read face session response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", fmt.Errorf("face verification service returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var parsed faceSessionResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, "", fmt.Errorf("failed to decode face session response: %w", err)
	}
	if parsed.FaceSessionID == "" {
		return nil, "", fmt.Errorf("face verification service returned empty session id")
	}

	return &FaceSession{
		FaceSessionID:    parsed.FaceSessionID,
		FaceSessionToken: parsed.FaceSessionToken,
		WebsocketURL:     parsed.WebsocketURL,
		BindingKeyReady:  parsed.BindingKeyReady,
	}, parsed.BindingSecret, nil
}

// sessionStatusResponse is the subset of GET /api/face/session/{id}/status we
// need. The face service nests the terminal verdict under "result".
type sessionStatusResponse struct {
	Status string `json:"status"` // created|connected|verifying|completed|failed|expired
	Result *struct {
		Result          string   `json:"result"` // success|failed|...
		MatchConfidence *float64 `json:"match_confidence"`
		LivenessPassed  *bool    `json:"liveness_passed"`
	} `json:"result"`
}

// GetSessionStatus implements FaceSessionStatusGetter.
func (c *FaceVerificationClient) GetSessionStatus(ctx context.Context, faceSessionID string) (*FaceVerificationResult, error) {
	endpoint := fmt.Sprintf("%s/api/face/session/%s/status", c.baseURL, url.PathEscape(faceSessionID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build face status request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call face verification status: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			slog.Error("failed to close face status response body", "error", cerr)
		}
	}()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read face status response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("face verification status returned %d: %s", resp.StatusCode, string(respBody))
	}

	var parsed sessionStatusResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("failed to decode face status response: %w", err)
	}

	// Prefer the explicit terminal verdict; fall back to a pending state.
	if parsed.Result != nil && parsed.Result.Result != "" {
		return &FaceVerificationResult{
			Status:          parsed.Result.Result,
			MatchConfidence: parsed.Result.MatchConfidence,
			LivenessPassed:  parsed.Result.LivenessPassed,
		}, nil
	}
	return &FaceVerificationResult{Status: faceStatusPending}, nil
}
