package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// irisStatusServer answers GET /internal/sessions/{id} with the given JSON.
func irisStatusServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/internal/sessions/fs_1", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The client turns the verifier's distance into this issuer's verdict, the way
// RegulaFaceClient turns a similarity into one. The verifier's own `passed` is
// carried through but decides nothing.
func TestIrisClientAppliesItsOwnThreshold(t *testing.T) {
	t.Run("distance at or under the threshold matches", func(t *testing.T) {
		srv := irisStatusServer(t, `{"status":"completed","passed":true,"distance":0.5,"frames":60,"duration_ms":4000}`)
		status, err := NewIrisClient(srv.URL, 0.5).GetSession(context.Background(), "fs_1")
		require.NoError(t, err)
		require.NotNil(t, status.Match)
		require.True(t, status.Match.Matched)
		require.InDelta(t, 0.5, status.Match.Score, 1e-9)
	})

	t.Run("a stricter threshold than the verifier's refuses", func(t *testing.T) {
		srv := irisStatusServer(t, `{"status":"completed","passed":true,"distance":0.61}`)
		status, err := NewIrisClient(srv.URL, 0.5).GetSession(context.Background(), "fs_1")
		require.NoError(t, err)
		require.NotNil(t, status.Match)
		require.False(t, status.Match.Matched)
		// The verifier's own verdict is still reported; it just does not decide.
		require.NotNil(t, status.Passed)
		require.True(t, *status.Passed)
	})

	t.Run("a laxer threshold than the verifier's accepts", func(t *testing.T) {
		srv := irisStatusServer(t, `{"status":"completed","passed":false,"distance":0.91}`)
		status, err := NewIrisClient(srv.URL, 0.95).GetSession(context.Background(), "fs_1")
		require.NoError(t, err)
		require.NotNil(t, status.Match)
		require.True(t, status.Match.Matched)
	})

	t.Run("no verdict before the engine completed", func(t *testing.T) {
		srv := irisStatusServer(t, `{"status":"streaming","frames":12}`)
		status, err := NewIrisClient(srv.URL, 0.5).GetSession(context.Background(), "fs_1")
		require.NoError(t, err)
		require.Nil(t, status.Match)
		require.Equal(t, irisStatusStreaming, status.Status)
	})

	t.Run("a completed session without a distance yields no verdict", func(t *testing.T) {
		srv := irisStatusServer(t, `{"status":"completed"}`)
		status, err := NewIrisClient(srv.URL, 0.5).GetSession(context.Background(), "fs_1")
		require.NoError(t, err)
		require.Nil(t, status.Match)
	})
}

func TestNewIrisClient(t *testing.T) {
	// The configured threshold is used as given; there is no default.
	require.Equal(t, 0.5, NewIrisClient("http://verifier:8081", 0.5).threshold)
	// The trailing slash is trimmed so session URLs do not double up.
	require.Equal(t, "http://verifier:8081", NewIrisClient("http://verifier:8081/", 0.5).baseURL)
}
