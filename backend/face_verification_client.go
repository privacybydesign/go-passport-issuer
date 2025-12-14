package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go-passport-issuer/models"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// FaceVerificationClient defines the interface for face verification operations
type FaceVerificationClient interface {
	// CheckLiveness retrieves liveness detection results for a given transaction
	CheckLiveness(transactionId string) (*models.LivenessCheckResponse, error)

	// MatchFaces compares two face images and returns a similarity score
	MatchFaces(image1, image2 string) (*models.FaceMatchResponse, error)

	// DetectFaces detects faces in an image and returns quality metrics
	DetectFaces(image string) (*models.FaceDetectResponse, error)

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

// CheckLiveness retrieves liveness detection results from Regula Face API
func (c *RegulaFaceClient) CheckLiveness(transactionId string) (*models.LivenessCheckResponse, error) {
	url := fmt.Sprintf("%s/api/v2/liveness?transactionId=%s", c.baseURL, transactionId)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create liveness request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute liveness request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("liveness check failed with status %d: %s", resp.StatusCode, string(body))
	}

	var regulaResponse struct {
		TransactionId string  `json:"transactionId"`
		Liveness      int     `json:"liveness"`
		Status        int     `json:"status"`
		Similarity    float64 `json:"similarity"`
		Tag           string  `json:"tag"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&regulaResponse); err != nil {
		return nil, fmt.Errorf("failed to decode liveness response: %w", err)
	}

	response := &models.LivenessCheckResponse{
		TransactionId: regulaResponse.TransactionId,
		Liveness:      regulaResponse.Liveness,
		Status:        regulaResponse.Status,
		Similarity:    regulaResponse.Similarity,
		Tag:           regulaResponse.Tag,
	}

	slog.Info("Liveness check completed",
		"transaction_id", transactionId,
		"liveness", regulaResponse.Liveness,
		"similarity", regulaResponse.Similarity)

	return response, nil
}

// MatchFaces compares two face images using Regula Face API
func (c *RegulaFaceClient) MatchFaces(image1, image2 string) (*models.FaceMatchResponse, error) {
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
		DetectedFaces []struct {
			Quality    float64 `json:"quality"`
			Crop       string  `json:"crop"`
			Attributes struct {
				Age     int    `json:"age"`
				Gender  string `json:"gender"`
				Glasses bool   `json:"glasses"`
			} `json:"attributes"`
		} `json:"detections"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&regulaResponse); err != nil {
		return nil, fmt.Errorf("failed to decode match response: %w", err)
	}

	var similarity float64
	if len(regulaResponse.Results) > 0 {
		similarity = regulaResponse.Results[0].Similarity
	}

	// Convert detected faces
	detectedFaces := make([]models.DetectedFace, 0, len(regulaResponse.DetectedFaces))
	for _, face := range regulaResponse.DetectedFaces {
		detectedFaces = append(detectedFaces, models.DetectedFace{
			Quality: face.Quality,
			Crop:    face.Crop,
			Attributes: &models.FaceAttributes{
				Age:     face.Attributes.Age,
				Gender:  face.Attributes.Gender,
				Glasses: face.Attributes.Glasses,
			},
		})
	}

	// Default threshold of 0.75 for matching (can be made configurable)
	matched := similarity >= 0.75

	response := &models.FaceMatchResponse{
		Similarity:    similarity,
		Matched:       matched,
		DetectedFaces: detectedFaces,
	}

	slog.Info("Face match completed", "similarity", similarity, "matched", matched)

	return response, nil
}

// DetectFaces detects faces in an image using Regula Face API
func (c *RegulaFaceClient) DetectFaces(image string) (*models.FaceDetectResponse, error) {
	url := fmt.Sprintf("%s/api/detect", c.baseURL)

	requestBody := map[string]interface{}{
		"image": image,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal detect request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create detect request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute detect request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("face detection failed with status %d: %s", resp.StatusCode, string(body))
	}

	var regulaResponse struct {
		Results []struct {
			Quality    float64 `json:"quality"`
			Crop       string  `json:"crop"`
			Attributes struct {
				Age     int    `json:"age"`
				Gender  string `json:"gender"`
				Glasses bool   `json:"glasses"`
			} `json:"attributes"`
		} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&regulaResponse); err != nil {
		return nil, fmt.Errorf("failed to decode detect response: %w", err)
	}

	detectedFaces := make([]models.DetectedFace, 0, len(regulaResponse.Results))
	for _, face := range regulaResponse.Results {
		detectedFaces = append(detectedFaces, models.DetectedFace{
			Quality: face.Quality,
			Crop:    face.Crop,
			Attributes: &models.FaceAttributes{
				Age:     face.Attributes.Age,
				Gender:  face.Attributes.Gender,
				Glasses: face.Attributes.Glasses,
			},
		})
	}

	response := &models.FaceDetectResponse{
		DetectedFaces: detectedFaces,
	}

	slog.Info("Face detection completed", "faces_detected", len(detectedFaces))

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
