package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// FaceMatchResponse represents the result of a face matching operation
type FaceMatchResponse struct {
	Similarity    float64 `json:"similarity"` // 0-1 similarity score
	Matched       bool    `json:"matched"`    // Whether faces match based on threshold
}

// FaceVerificationClient defines the interface for face verification operations
type FaceVerificationClient interface {
	// MatchFaces compares two face images and returns a similarity score
	MatchFaces(image1, image2 string) (*FaceMatchResponse, error)

	// HealthCheck verifies the Regula Face API service is available
	HealthCheck() error
}

// RegulaFaceClient implements the FaceVerificationClient interface
type RegulaFaceClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewRegulaFaceClient creates a new instance of RegulaFaceClient
func NewRegulaFaceClient(baseURL string) *RegulaFaceClient {
	return &RegulaFaceClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// MatchFaces compares two face images using Regula Face API
func (c *RegulaFaceClient) MatchFaces(image1, image2 string) (*FaceMatchResponse, error) {
	url := fmt.Sprintf("%s/api/match", c.baseURL)

	requestBody := map[string]interface{}{
		"images": []map[string]interface{}{
			{
				"type":  1, // First image
				"data":  image1,
				"index": 1,
			},
			{
				"type":  2, // Second image
				"data":  image2,
				"index": 2,
			},
		},
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal match request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create match request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute match request: %w", err)
	}
	defer resp.Body.Close()

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

	// Default threshold of 0.75 for matching (can be made configurable)
	matched := similarity >= 0.75

	response := &FaceMatchResponse{
		Similarity: similarity,
		Matched:    matched,
	}

	slog.Info("Face match completed", "similarity", similarity, "matched", matched)

	return response, nil
}

// HealthCheck verifies the Regula Face API service is available
func (c *RegulaFaceClient) HealthCheck() error {
	url := fmt.Sprintf("%s/api/healthz", c.baseURL)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute health check request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("health check failed with status %d: %s", resp.StatusCode, string(body))
	}

	slog.Info("Regula Face API health check passed")
	return nil
}
