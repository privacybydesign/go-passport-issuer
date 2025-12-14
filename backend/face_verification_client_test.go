package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegulaFaceClient_HealthCheck(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/healthz" {
			t.Errorf("Expected path /api/healthz, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	client := NewRegulaFaceClient(server.URL)
	err := client.HealthCheck()
	if err != nil {
		t.Errorf("HealthCheck failed: %v", err)
	}
}

func TestRegulaFaceClient_CheckLiveness_Success(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/liveness" {
			t.Errorf("Expected path /api/v2/liveness, got %s", r.URL.Path)
		}

		transactionId := r.URL.Query().Get("transactionId")
		if transactionId != "test-transaction-123" {
			t.Errorf("Expected transactionId test-transaction-123, got %s", transactionId)
		}

		response := map[string]interface{}{
			"transactionId": transactionId,
			"liveness":      0,
			"status":        1,
			"similarity":    0.95,
			"tag":           "test",
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewRegulaFaceClient(server.URL)
	result, err := client.CheckLiveness("test-transaction-123")

	if err != nil {
		t.Errorf("CheckLiveness failed: %v", err)
	}

	if result.TransactionId != "test-transaction-123" {
		t.Errorf("Expected transactionId test-transaction-123, got %s", result.TransactionId)
	}

	if result.Liveness != 0 {
		t.Errorf("Expected liveness 0, got %d", result.Liveness)
	}

	if result.Similarity != 0.95 {
		t.Errorf("Expected similarity 0.95, got %f", result.Similarity)
	}
}

func TestRegulaFaceClient_MatchFaces_Success(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/match" {
			t.Errorf("Expected path /api/match, got %s", r.URL.Path)
		}

		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}

		response := map[string]interface{}{
			"results": []map[string]interface{}{
				{"similarity": 0.87},
			},
			"detections": []map[string]interface{}{
				{
					"quality": 0.92,
					"crop":    "base64encodedimage",
					"attributes": map[string]interface{}{
						"age":     30,
						"gender":  "male",
						"glasses": false,
					},
				},
			},
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewRegulaFaceClient(server.URL)
	result, err := client.MatchFaces("image1base64", "image2base64")

	if err != nil {
		t.Errorf("MatchFaces failed: %v", err)
	}

	if result.Similarity != 0.87 {
		t.Errorf("Expected similarity 0.87, got %f", result.Similarity)
	}

	if !result.Matched {
		t.Error("Expected matched to be true")
	}

	if len(result.DetectedFaces) != 1 {
		t.Errorf("Expected 1 detected face, got %d", len(result.DetectedFaces))
	}
}

func TestRegulaFaceClient_DetectFaces_Success(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/detect" {
			t.Errorf("Expected path /api/detect, got %s", r.URL.Path)
		}

		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}

		response := map[string]interface{}{
			"results": []map[string]interface{}{
				{
					"quality": 0.88,
					"crop":    "base64encodedface1",
					"attributes": map[string]interface{}{
						"age":     25,
						"gender":  "female",
						"glasses": true,
					},
				},
				{
					"quality": 0.91,
					"crop":    "base64encodedface2",
					"attributes": map[string]interface{}{
						"age":     35,
						"gender":  "male",
						"glasses": false,
					},
				},
			},
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewRegulaFaceClient(server.URL)
	result, err := client.DetectFaces("imagebase64")

	if err != nil {
		t.Errorf("DetectFaces failed: %v", err)
	}

	if len(result.DetectedFaces) != 2 {
		t.Errorf("Expected 2 detected faces, got %d", len(result.DetectedFaces))
	}

	firstFace := result.DetectedFaces[0]
	if firstFace.Quality != 0.88 {
		t.Errorf("Expected quality 0.88, got %f", firstFace.Quality)
	}

	if firstFace.Attributes.Age != 25 {
		t.Errorf("Expected age 25, got %d", firstFace.Attributes.Age)
	}
}

func TestRegulaFaceClient_CheckLiveness_Error(t *testing.T) {
	// Create a mock server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid transaction id"))
	}))
	defer server.Close()

	client := NewRegulaFaceClient(server.URL)
	_, err := client.CheckLiveness("invalid-transaction")

	if err == nil {
		t.Error("Expected error but got none")
	}
}

func TestNewRegulaFaceClient(t *testing.T) {
	baseURL := "http://localhost:41101"
	client := NewRegulaFaceClient(baseURL)

	if client == nil {
		t.Error("Expected client to be created")
	}

	if client.baseURL != baseURL {
		t.Errorf("Expected baseURL %s, got %s", baseURL, client.baseURL)
	}

	if client.httpClient == nil {
		t.Error("Expected httpClient to be initialized")
	}
}
