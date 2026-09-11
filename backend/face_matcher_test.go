package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// sidecarStub serves a canned /match response and records what it received.
type sidecarStub struct {
	t        *testing.T
	response sidecarMatchResponse
	status   int
	gotDoc   []byte
	gotLive  []byte
	calls    int
}

func (s *sidecarStub) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/match", func(w http.ResponseWriter, r *http.Request) {
		s.calls++
		require.Equal(s.t, http.MethodPost, r.Method)
		require.Equal(s.t, "application/json", r.Header.Get("Content-Type"))

		var req sidecarMatchRequest
		require.NoError(s.t, json.NewDecoder(r.Body).Decode(&req))
		var err error
		s.gotDoc, err = base64.StdEncoding.DecodeString(req.DocumentImage)
		require.NoError(s.t, err)
		s.gotLive, err = base64.StdEncoding.DecodeString(req.LiveImage)
		require.NoError(s.t, err)

		if s.status != 0 && s.status != http.StatusOK {
			http.Error(w, "engine exploded", s.status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		require.NoError(s.t, json.NewEncoder(w).Encode(s.response))
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if s.status != 0 && s.status != http.StatusOK {
			http.Error(w, "model not loaded", s.status)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	return mux
}

func newSidecarStub(t *testing.T, response sidecarMatchResponse, status int) (*sidecarStub, *httptest.Server) {
	t.Helper()
	stub := &sidecarStub{t: t, response: response, status: status}
	server := httptest.NewServer(stub.handler())
	t.Cleanup(server.Close)
	return stub, server
}

func TestSidecarFaceMatcher_MatchImages_Success(t *testing.T) {
	stub, server := newSidecarStub(t, sidecarMatchResponse{Similarity: 0.71, DocumentFaces: 1, LiveFaces: 1}, http.StatusOK)
	matcher := NewSidecarFaceMatcher(server.URL, 0.5)

	result, err := matcher.MatchImages([]byte("doc-bytes"), []byte("live-bytes"))
	require.NoError(t, err)
	require.True(t, result.Matched)
	require.Equal(t, 0.71, result.Similarity)

	// The images must reach the sidecar byte-for-byte, base64 is transport only.
	require.Equal(t, 1, stub.calls)
	require.Equal(t, []byte("doc-bytes"), stub.gotDoc)
	require.Equal(t, []byte("live-bytes"), stub.gotLive)
}

func TestSidecarFaceMatcher_MatchImages_BelowThreshold(t *testing.T) {
	_, server := newSidecarStub(t, sidecarMatchResponse{Similarity: 0.3, DocumentFaces: 1, LiveFaces: 1}, http.StatusOK)
	matcher := NewSidecarFaceMatcher(server.URL, 0.5)

	result, err := matcher.MatchImages([]byte("doc"), []byte("live"))
	require.NoError(t, err)
	require.False(t, result.Matched)
	require.Equal(t, 0.3, result.Similarity)
}

// A high similarity never counts when the live image holds more than one face:
// the issuer cannot tell which face the score belongs to.
func TestSidecarFaceMatcher_MatchImages_RejectsMultipleFaces(t *testing.T) {
	_, server := newSidecarStub(t, sidecarMatchResponse{Similarity: 0.95, DocumentFaces: 1, LiveFaces: 2}, http.StatusOK)
	matcher := NewSidecarFaceMatcher(server.URL, 0.5)

	result, err := matcher.MatchImages([]byte("doc"), []byte("live"))
	require.NoError(t, err)
	require.False(t, result.Matched)
}

func TestSidecarFaceMatcher_MatchImages_RejectsNoDocumentFace(t *testing.T) {
	_, server := newSidecarStub(t, sidecarMatchResponse{Similarity: 0.95, DocumentFaces: 0, LiveFaces: 1}, http.StatusOK)
	matcher := NewSidecarFaceMatcher(server.URL, 0.5)

	result, err := matcher.MatchImages([]byte("doc"), []byte("live"))
	require.NoError(t, err)
	require.False(t, result.Matched)
}

func TestSidecarFaceMatcher_MatchImages_ServerError(t *testing.T) {
	_, server := newSidecarStub(t, sidecarMatchResponse{}, http.StatusInternalServerError)
	matcher := NewSidecarFaceMatcher(server.URL, 0.5)

	result, err := matcher.MatchImages([]byte("doc"), []byte("live"))
	require.Error(t, err)
	require.Nil(t, result)
	require.ErrorContains(t, err, "500")
}

func TestSidecarFaceMatcher_MatchImages_Unreachable(t *testing.T) {
	matcher := NewSidecarFaceMatcher("http://127.0.0.1:1", 0.5)
	result, err := matcher.MatchImages([]byte("doc"), []byte("live"))
	require.Error(t, err)
	require.Nil(t, result)
}

func TestSidecarFaceMatcher_MatchImages_RequiresBothImages(t *testing.T) {
	stub, server := newSidecarStub(t, sidecarMatchResponse{Similarity: 1, DocumentFaces: 1, LiveFaces: 1}, http.StatusOK)
	matcher := NewSidecarFaceMatcher(server.URL, 0.5)

	_, err := matcher.MatchImages(nil, []byte("live"))
	require.Error(t, err)
	_, err = matcher.MatchImages([]byte("doc"), nil)
	require.Error(t, err)
	require.Equal(t, 0, stub.calls, "nothing may be sent without both images")
}

func TestSidecarFaceMatcher_HealthCheck(t *testing.T) {
	_, healthy := newSidecarStub(t, sidecarMatchResponse{}, http.StatusOK)
	require.NoError(t, NewSidecarFaceMatcher(healthy.URL, 0.5).HealthCheck())

	_, unhealthy := newSidecarStub(t, sidecarMatchResponse{}, http.StatusServiceUnavailable)
	require.Error(t, NewSidecarFaceMatcher(unhealthy.URL, 0.5).HealthCheck())

	require.Error(t, NewSidecarFaceMatcher("http://127.0.0.1:1", 0.5).HealthCheck())
}
