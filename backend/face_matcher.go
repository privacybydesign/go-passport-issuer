package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// FaceMatcher compares two face images and reports how similar they are. It
// is the server-side check behind variant B (on-device face verification):
// the app's verdict is never trusted on its own, the issuer re-matches the
// live face crop the on-device SDK returned against the chip portrait.
//
// Deliberately has no Regula implementation. Variant B must work in an
// environment where Regula is not deployed at all.
type FaceMatcher interface {
	// MatchImages compares the document (chip) portrait with a live face
	// image. Both are raw encoded image bytes (PNG, JPEG or JPEG 2000).
	MatchImages(documentImage, liveImage []byte) (*FaceMatchResponse, error)

	// HealthCheck verifies the matcher is reachable and has its model loaded.
	HealthCheck() error
}

// SidecarFaceMatcher talks to the self-hosted face-matcher sidecar (see
// face-matcher/ in the repository root): an open-source ArcFace model behind
// a two-endpoint HTTP API, POST /match and GET /healthz.
type SidecarFaceMatcher struct {
	baseURL    string
	threshold  float64
	httpClient *http.Client
}

// NewSidecarFaceMatcher creates a client for the face-matcher sidecar. The
// threshold is the cosine similarity above which two faces are considered the
// same person. There is no default: ArcFace similarities are on a different
// scale than Regula's score, so the value has to be calibrated per deployment
// (config validation rejects a non-positive threshold).
func NewSidecarFaceMatcher(baseURL string, threshold float64) *SidecarFaceMatcher {
	return &SidecarFaceMatcher{
		baseURL:   baseURL,
		threshold: threshold,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// sidecarMatchRequest is the body of POST /match. Images travel base64
// encoded inside JSON so the sidecar API stays a single, easily mocked call.
type sidecarMatchRequest struct {
	DocumentImage string `json:"document_image"`
	LiveImage     string `json:"live_image"`
}

// sidecarMatchResponse is the body the sidecar returns. Face counts are
// reported separately so the issuer, not the sidecar, decides that anything
// other than exactly one face on each side is a failed match.
type sidecarMatchResponse struct {
	Similarity    float64 `json:"similarity"`
	DocumentFaces int     `json:"document_faces"`
	LiveFaces     int     `json:"live_faces"`
}

// MatchImages sends both images to the sidecar and applies the configured
// threshold. A match additionally requires exactly one detected face in each
// image: a crop with two faces, or a portrait the detector cannot find a face
// in, never matches regardless of similarity.
func (m *SidecarFaceMatcher) MatchImages(documentImage, liveImage []byte) (*FaceMatchResponse, error) {
	if len(documentImage) == 0 || len(liveImage) == 0 {
		return nil, fmt.Errorf("both a document image and a live image are required")
	}

	body, err := json.Marshal(sidecarMatchRequest{
		DocumentImage: base64.StdEncoding.EncodeToString(documentImage),
		LiveImage:     base64.StdEncoding.EncodeToString(liveImage),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal match request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, m.baseURL+"/match", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create match request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute match request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Cap what we read from an error body so a misbehaving sidecar cannot
		// balloon a log line.
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("face matcher returned status %d: %s", resp.StatusCode, string(errBody))
	}

	var result sidecarMatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode match response: %w", err)
	}

	oneFaceEach := result.DocumentFaces == 1 && result.LiveFaces == 1
	matched := oneFaceEach && result.Similarity >= m.threshold

	slog.Info("Face match completed",
		"matcher", "sidecar",
		"similarity", result.Similarity,
		"threshold", m.threshold,
		"document_faces", result.DocumentFaces,
		"live_faces", result.LiveFaces,
		"matched", matched)

	return &FaceMatchResponse{
		Similarity: result.Similarity,
		Matched:    matched,
	}, nil
}

// HealthCheck calls GET /healthz on the sidecar.
func (m *SidecarFaceMatcher) HealthCheck() error {
	req, err := http.NewRequest(http.MethodGet, m.baseURL+"/healthz", nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute health check request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("face matcher health check failed with status %d: %s", resp.StatusCode, string(errBody))
	}

	slog.Info("Face matcher health check passed")
	return nil
}
