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

// IrisSession is what the verifier returns when the issuer opens a face
// session. The token goes to the wallet, which presents it on the stream; the
// issuer never uses it itself.
type IrisSession struct {
	FaceSessionID string    `json:"face_session_id"`
	Token         string    `json:"token"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// Iris session statuses as reported by the verifier's internal API.
const (
	irisStatusPending   = "pending"
	irisStatusStreaming = "streaming"
	irisStatusCompleted = "completed"
	irisStatusFailed    = "failed"
	irisStatusExpired   = "expired"
)

// IrisSessionStatus is the verifier's view of one face session.
type IrisSessionStatus struct {
	Status string `json:"status"`
	// Passed and Distance are set once the status is completed. Passed is the
	// verifier's decision (distance at or under its threshold); the issuer gates
	// on it rather than re-deciding.
	Passed         *bool    `json:"passed,omitempty"`
	Distance       *float64 `json:"distance,omitempty"`
	PortraitSha256 string   `json:"portrait_sha256"`
	Frames         int      `json:"frames"`
	DurationMs     int64    `json:"duration_ms"`
}

// IrisClient talks to the Iris verifier's cluster-internal API. Mirrors the
// shape of FaceVerificationClient so the two methods sit side by side.
type IrisClient interface {
	// CreateSession opens a face session bound to the given portrait (the raw
	// chip image, base64-encoded) and its hash.
	CreateSession(ctx context.Context, portraitBase64, portraitSha256, documentType string) (*IrisSession, error)
	// GetSession returns the session's current status and, when completed, its
	// verdict.
	GetSession(ctx context.Context, faceSessionID string) (*IrisSessionStatus, error)
	// DeleteSession removes the session once the issuer has pulled its
	// verdict.
	DeleteSession(ctx context.Context, faceSessionID string) error
	// HealthCheck verifies the verifier is reachable.
	HealthCheck() error
}

// HTTPIrisClient implements IrisClient over the verifier's internal HTTP API.
type HTTPIrisClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewIrisClient creates a client for the verifier at baseURL (cluster-internal,
// e.g. http://iris-verifier-svc:8081).
func NewIrisClient(baseURL string) *HTTPIrisClient {
	return &HTTPIrisClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *HTTPIrisClient) CreateSession(ctx context.Context, portraitBase64, portraitSha256, documentType string) (*IrisSession, error) {
	if portraitBase64 == "" {
		return nil, fmt.Errorf("portrait is empty")
	}
	body, err := json.Marshal(map[string]string{
		"portrait":        portraitBase64,
		"portrait_sha256": portraitSha256,
		"document_type":   documentType,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal iris session request: %w", err)
	}
	respBody, err := c.do(ctx, http.MethodPost, c.baseURL+"/internal/sessions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	var session IrisSession
	if err := json.Unmarshal(respBody, &session); err != nil {
		return nil, fmt.Errorf("failed to decode iris session response: %w", err)
	}
	if session.FaceSessionID == "" || session.Token == "" {
		return nil, fmt.Errorf("iris verifier returned an incomplete session")
	}
	slog.Info("Iris face session opened", "face_session_id", session.FaceSessionID)
	return &session, nil
}

func (c *HTTPIrisClient) GetSession(ctx context.Context, faceSessionID string) (*IrisSessionStatus, error) {
	respBody, err := c.do(ctx, http.MethodGet, c.sessionURL(faceSessionID), nil)
	if err != nil {
		return nil, err
	}
	var status IrisSessionStatus
	if err := json.Unmarshal(respBody, &status); err != nil {
		return nil, fmt.Errorf("failed to decode iris session status: %w", err)
	}
	return &status, nil
}

func (c *HTTPIrisClient) DeleteSession(ctx context.Context, faceSessionID string) error {
	_, err := c.do(ctx, http.MethodDelete, c.sessionURL(faceSessionID), nil)
	return err
}

func (c *HTTPIrisClient) HealthCheck() error {
	resp, err := c.httpClient.Get(c.baseURL + "/healthz")
	if err != nil {
		return fmt.Errorf("failed to execute iris health check: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("iris health check failed with status %d: %s", resp.StatusCode, string(body))
	}
	slog.Info("Iris verifier health check passed")
	return nil
}

func (c *HTTPIrisClient) sessionURL(faceSessionID string) string {
	return c.baseURL + "/internal/sessions/" + url.PathEscape(faceSessionID)
}

// do performs one request and returns the body of a 2xx response.
func (c *HTTPIrisClient) do(ctx context.Context, method, target string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create iris request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call iris verifier: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read iris response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("iris verifier returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return respBody, nil
}
