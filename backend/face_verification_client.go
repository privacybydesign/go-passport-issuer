package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// DefaultFaceMatchThreshold is the similarity threshold used to decide whether
// two faces match when none is configured.
const DefaultFaceMatchThreshold = 0.75

// Regula ImageSource types (see the Face SDK OpenAPI ImageSource enum).
const (
	regulaImageSourceDocumentRFID = 2 // portrait read from the document chip (DG2/DG6)
	regulaImageSourceLive         = 3 // a live capture / selfie
)

// FaceMatchResponse represents the result of a face matching operation.
type FaceMatchResponse struct {
	Similarity float64 `json:"similarity"` // 0-1 similarity score
	Matched    bool    `json:"matched"`    // Whether faces match based on threshold
}

// LivenessStatus represents the outcome of a Regula liveness transaction.
type LivenessStatus struct {
	// Confirmed is true when the liveness check determined a real, live person.
	Confirmed bool
	// Code is the raw FaceSDKResultCode returned by Regula.
	Code int
}

// FaceVerificationClient defines the interface for face verification operations.
type FaceVerificationClient interface {
	// MatchFaceWithLiveness compares the document (chip) portrait against the live
	// face captured during a Regula liveness session, identified by its transaction ID.
	MatchFaceWithLiveness(documentImage, livenessTransactionID string) (*FaceMatchResponse, error)

	// GetLivenessStatus retrieves a liveness transaction and reports whether the
	// captured face was confirmed to be a real, live person.
	GetLivenessStatus(livenessTransactionID string) (*LivenessStatus, error)

	// DeleteLivenessTransaction removes the stored liveness session data (portrait,
	// video and metadata) once it is no longer needed.
	DeleteLivenessTransaction(livenessTransactionID string) error

	// HealthCheck verifies the Regula Face API service is available.
	HealthCheck() error
}

// RegulaFaceClient implements the FaceVerificationClient interface.
type RegulaFaceClient struct {
	baseURL    string
	threshold  float64
	httpClient *http.Client
}

// NewRegulaFaceClient creates a new instance of RegulaFaceClient. A threshold of
// 0 (or less) falls back to DefaultFaceMatchThreshold.
func NewRegulaFaceClient(baseURL string, threshold float64) *RegulaFaceClient {
	if threshold <= 0 {
		threshold = DefaultFaceMatchThreshold
	}
	return &RegulaFaceClient{
		baseURL:   baseURL,
		threshold: threshold,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// MatchFaceWithLiveness compares the document chip portrait against the live face
// captured during a liveness session using Regula's POST /api/match endpoint. The
// live face is referenced by its liveness transaction ID rather than supplied as a
// raw image, so the match is bound to a face Regula already validated as live.
func (c *RegulaFaceClient) MatchFaceWithLiveness(documentImage, livenessTransactionID string) (*FaceMatchResponse, error) {
	matchURL := fmt.Sprintf("%s/api/match", c.baseURL)

	requestBody := map[string]any{
		"images": []map[string]any{
			{
				"type":  regulaImageSourceDocumentRFID,
				"data":  documentImage,
				"index": 1,
			},
			{
				"type":                  regulaImageSourceLive,
				"livenessTransactionId": livenessTransactionID,
				"index":                 2,
			},
		},
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal match request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, matchURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create match request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute match request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("face match failed with status %d: %s", resp.StatusCode, string(body))
	}

	var regulaResponse struct {
		Results []struct {
			Similarity float64 `json:"similarity"`
		} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&regulaResponse); err != nil {
		return nil, fmt.Errorf("failed to decode match response: %w", err)
	}

	var similarity float64
	if len(regulaResponse.Results) > 0 {
		similarity = regulaResponse.Results[0].Similarity
	}

	matched := similarity >= c.threshold

	slog.Info("Face match completed", "similarity", similarity, "threshold", c.threshold, "matched", matched)

	return &FaceMatchResponse{
		Similarity: similarity,
		Matched:    matched,
	}, nil
}

// GetLivenessStatus retrieves a liveness transaction via GET /api/v2/liveness and
// reports whether the captured face was confirmed live. Regula reports a status of
// 0 when liveness is confirmed.
func (c *RegulaFaceClient) GetLivenessStatus(livenessTransactionID string) (*LivenessStatus, error) {
	livenessURL := fmt.Sprintf("%s/api/v2/liveness?transactionId=%s", c.baseURL, url.QueryEscape(livenessTransactionID))

	req, err := http.NewRequest(http.MethodGet, livenessURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create liveness status request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute liveness status request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("liveness status request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var transactionInfo struct {
		Code   int `json:"code"`
		Status int `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&transactionInfo); err != nil {
		return nil, fmt.Errorf("failed to decode liveness status response: %w", err)
	}

	status := &LivenessStatus{
		Confirmed: transactionInfo.Status == 0,
		Code:      transactionInfo.Code,
	}

	slog.Info("Liveness status retrieved", "confirmed", status.Confirmed, "code", status.Code)
	return status, nil
}

// DeleteLivenessTransaction removes a liveness transaction via DELETE
// /api/v2/liveness so the stored biometric session data is not retained.
func (c *RegulaFaceClient) DeleteLivenessTransaction(livenessTransactionID string) error {
	livenessURL := fmt.Sprintf("%s/api/v2/liveness?transactionId=%s", c.baseURL, url.QueryEscape(livenessTransactionID))

	req, err := http.NewRequest(http.MethodDelete, livenessURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create liveness delete request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute liveness delete request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Regula returns 204 No Content on success; tolerate 200 as well.
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("liveness delete failed with status %d: %s", resp.StatusCode, string(body))
	}

	slog.Info("Liveness transaction deleted")
	return nil
}

// HealthCheck verifies the Regula Face API service is available.
func (c *RegulaFaceClient) HealthCheck() error {
	healthURL := fmt.Sprintf("%s/api/healthz", c.baseURL)

	req, err := http.NewRequest(http.MethodGet, healthURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute health check request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("health check failed with status %d: %s", resp.StatusCode, string(body))
	}

	slog.Info("Regula Face API health check passed")
	return nil
}
