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
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	client := NewRegulaFaceClient(server.URL, 0)
	err := client.HealthCheck()
	if err != nil {
		t.Errorf("HealthCheck failed: %v", err)
	}
}

func TestRegulaFaceClient_MatchFaceWithLiveness_Success(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/match" {
			t.Errorf("Expected path /api/match, got %s", r.URL.Path)
		}

		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}

		// Verify the request carries the chip image and the liveness transaction id.
		var body struct {
			Images []struct {
				Type                  int    `json:"type"`
				Data                  string `json:"data"`
				LivenessTransactionID string `json:"livenessTransactionId"`
			} `json:"images"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode match request: %v", err)
		}
		if len(body.Images) != 2 {
			t.Fatalf("expected 2 images, got %d", len(body.Images))
		}
		if body.Images[0].Type != regulaImageSourceDocumentRFID || body.Images[0].Data != "chipImageBase64" {
			t.Errorf("unexpected document image entry: %+v", body.Images[0])
		}
		if body.Images[1].Type != regulaImageSourceLive || body.Images[1].LivenessTransactionID != "txn-123" {
			t.Errorf("unexpected live image entry: %+v", body.Images[1])
		}

		response := map[string]any{
			"results": []map[string]any{
				{"similarity": 0.87},
			},
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewRegulaFaceClient(server.URL, 0)
	result, err := client.MatchFaceWithLiveness("chipImageBase64", "txn-123")

	if err != nil {
		t.Errorf("MatchFaceWithLiveness failed: %v", err)
	}

	if result.Similarity != 0.87 {
		t.Errorf("Expected similarity 0.87, got %f", result.Similarity)
	}

	if !result.Matched {
		t.Error("Expected matched to be true")
	}
}

func TestRegulaFaceClient_GetLivenessStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/liveness" {
			t.Errorf("Expected path /api/v2/liveness, got %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("transactionId"); got != "txn-123" {
			t.Errorf("Expected transactionId txn-123, got %s", got)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "status": 0})
	}))
	defer server.Close()

	client := NewRegulaFaceClient(server.URL, 0)
	status, err := client.GetLivenessStatus("txn-123")
	if err != nil {
		t.Fatalf("GetLivenessStatus failed: %v", err)
	}
	if !status.Confirmed {
		t.Error("Expected liveness to be confirmed for status 0")
	}
}

func TestRegulaFaceClient_GetLivenessStatus_NotConfirmed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"code": 0, "status": 1})
	}))
	defer server.Close()

	client := NewRegulaFaceClient(server.URL, 0)
	status, err := client.GetLivenessStatus("txn-123")
	if err != nil {
		t.Fatalf("GetLivenessStatus failed: %v", err)
	}
	if status.Confirmed {
		t.Error("Expected liveness to be not confirmed for status 1")
	}
}

func TestRegulaFaceClient_DeleteLivenessTransaction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("Expected DELETE method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v2/liveness" {
			t.Errorf("Expected path /api/v2/liveness, got %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("transactionId"); got != "txn-123" {
			t.Errorf("Expected transactionId txn-123, got %s", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewRegulaFaceClient(server.URL, 0)
	if err := client.DeleteLivenessTransaction("txn-123"); err != nil {
		t.Errorf("DeleteLivenessTransaction failed: %v", err)
	}
}

func TestNewRegulaFaceClient(t *testing.T) {
	baseURL := "http://localhost:41101"
	client := NewRegulaFaceClient(baseURL, 0)

	if client == nil {
		t.Fatal("Expected client to be created")
	}

	if client.baseURL != baseURL {
		t.Errorf("Expected baseURL %s, got %s", baseURL, client.baseURL)
	}

	if client.threshold != DefaultFaceMatchThreshold {
		t.Errorf("Expected default threshold %f, got %f", DefaultFaceMatchThreshold, client.threshold)
	}

	if client.httpClient == nil {
		t.Error("Expected httpClient to be initialized")
	}

	custom := NewRegulaFaceClient(baseURL, 0.9)
	if custom.threshold != 0.9 {
		t.Errorf("Expected threshold 0.9, got %f", custom.threshold)
	}
}
