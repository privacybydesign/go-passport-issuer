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
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "status": 1})
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

// badURLClient returns a client whose base URL contains a control character so
// that http.NewRequest fails when building any request.
func badURLClient() *RegulaFaceClient {
	return NewRegulaFaceClient("http://\x7f", 0)
}

// unreachableClient returns a client pointing at a server that has been closed,
// so the HTTP round-trip fails.
func unreachableClient(t *testing.T) *RegulaFaceClient {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := server.URL
	server.Close()
	return NewRegulaFaceClient(url, 0)
}

// clientReturningStatus returns a client backed by a server that always responds
// with the given status code, along with a cleanup function.
func clientReturningStatus(t *testing.T, status int) (*RegulaFaceClient, func()) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
	return NewRegulaFaceClient(server.URL, 0), server.Close
}

// clientReturningBody returns a client backed by a server that responds 200 with
// the given raw body, along with a cleanup function.
func clientReturningBody(t *testing.T, body string) (*RegulaFaceClient, func()) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	return NewRegulaFaceClient(server.URL, 0), server.Close
}

func TestRegulaFaceClient_ErrorPaths(t *testing.T) {
	t.Run("MatchFaceWithLiveness_RequestBuildError", func(t *testing.T) {
		_, err := badURLClient().MatchFaceWithLiveness("img", "txn")
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("MatchFaceWithLiveness_TransportError", func(t *testing.T) {
		_, err := unreachableClient(t).MatchFaceWithLiveness("img", "txn")
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("MatchFaceWithLiveness_NonOKStatus", func(t *testing.T) {
		client, cleanup := clientReturningStatus(t, http.StatusInternalServerError)
		defer cleanup()
		if _, err := client.MatchFaceWithLiveness("img", "txn"); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("MatchFaceWithLiveness_BadJSON", func(t *testing.T) {
		client, cleanup := clientReturningBody(t, "not-json")
		defer cleanup()
		if _, err := client.MatchFaceWithLiveness("img", "txn"); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("GetLivenessStatus_RequestBuildError", func(t *testing.T) {
		_, err := badURLClient().GetLivenessStatus("txn")
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("GetLivenessStatus_TransportError", func(t *testing.T) {
		_, err := unreachableClient(t).GetLivenessStatus("txn")
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("GetLivenessStatus_NonOKStatus", func(t *testing.T) {
		client, cleanup := clientReturningStatus(t, http.StatusNotFound)
		defer cleanup()
		if _, err := client.GetLivenessStatus("txn"); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("GetLivenessStatus_BadJSON", func(t *testing.T) {
		client, cleanup := clientReturningBody(t, "not-json")
		defer cleanup()
		if _, err := client.GetLivenessStatus("txn"); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("DeleteLivenessTransaction_RequestBuildError", func(t *testing.T) {
		if err := badURLClient().DeleteLivenessTransaction("txn"); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("DeleteLivenessTransaction_TransportError", func(t *testing.T) {
		if err := unreachableClient(t).DeleteLivenessTransaction("txn"); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("DeleteLivenessTransaction_NonOKStatus", func(t *testing.T) {
		client, cleanup := clientReturningStatus(t, http.StatusInternalServerError)
		defer cleanup()
		if err := client.DeleteLivenessTransaction("txn"); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("HealthCheck_RequestBuildError", func(t *testing.T) {
		if err := badURLClient().HealthCheck(); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("HealthCheck_TransportError", func(t *testing.T) {
		if err := unreachableClient(t).HealthCheck(); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("HealthCheck_NonOKStatus", func(t *testing.T) {
		client, cleanup := clientReturningStatus(t, http.StatusServiceUnavailable)
		defer cleanup()
		if err := client.HealthCheck(); err == nil {
			t.Fatal("expected error")
		}
	})
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
