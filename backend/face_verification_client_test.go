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
