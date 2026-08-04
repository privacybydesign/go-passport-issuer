package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

// TestSpaHandlerStatErrorReturnsGenericMessage verifies that when os.Stat
// returns an unexpected error (here ENOTDIR, by treating a regular file as a
// directory component), the handler responds with a generic 500 and does not
// leak the raw OS error string (which may contain filesystem paths / internals).
func TestSpaHandlerStatErrorReturnsGenericMessage(t *testing.T) {
	dir := t.TempDir()
	// Create a regular file; requesting a path *below* it makes os.Stat fail
	// with ENOTDIR, which is not os.IsNotExist.
	regularFile := filepath.Join(dir, "afile")
	require.NoError(t, os.WriteFile(regularFile, []byte("data"), 0o600))

	h := SpaHandler{staticPath: dir, indexPath: "index.html"}

	req := httptest.NewRequest(http.MethodGet, "/afile/child", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	body := rec.Body.String()
	require.Equal(t, "internal server error", strings.TrimSpace(body))
	// The response must not leak the server-side filesystem path.
	require.NotContains(t, body, dir)
	require.NotContains(t, body, "afile")
}

// TestSpaHandlerMissingFileServesIndex verifies the SPA fallback: a request for
// a path that does not exist serves index.html.
func TestSpaHandlerMissingFileServesIndex(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>spa</html>"), 0o600))

	h := SpaHandler{staticPath: dir, indexPath: "index.html"}

	req := httptest.NewRequest(http.MethodGet, "/does/not/exist", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "spa")
}

// docsRouter builds the server's router with the API docs flag set as given,
// without binding a port.
func docsRouter(t *testing.T, enableApiDocs bool) *mux.Router {
	t.Helper()

	config := testConfig
	config.EnableApiDocs = enableApiDocs

	srv, err := NewServer(&ServerState{}, config)
	require.NoError(t, err)

	router, ok := srv.server.Handler.(*mux.Router)
	require.True(t, ok, "server handler is not a *mux.Router")
	return router
}

func registeredPaths(t *testing.T, router *mux.Router) []string {
	t.Helper()

	var paths []string
	err := router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		if template, err := route.GetPathTemplate(); err == nil {
			paths = append(paths, template)
		}
		return nil
	})
	require.NoError(t, err)
	return paths
}

// TestApiDocsAbsentWhenDisabled verifies that the docs routes are not registered
// when enable_api_docs is off, and that neither document is served.
func TestApiDocsAbsentWhenDisabled(t *testing.T) {
	router := docsRouter(t, false)

	paths := registeredPaths(t, router)
	require.NotContains(t, paths, "/api/docs")
	require.NotContains(t, paths, "/api/docs/swagger.yaml")

	for _, path := range []string{"/api/docs", "/api/docs/swagger.yaml"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

		// The SPA catch-all takes the request, so the paths behave like any other
		// unknown path. What matters is that the docs themselves are not served.
		require.NotEqual(t, redocHTML, rec.Body.Bytes(), "redoc html served for %s", path)
		require.NotEqual(t, swaggerSpec, rec.Body.Bytes(), "swagger spec served for %s", path)
		require.NotEqual(t, "application/x-yaml", rec.Header().Get("Content-Type"))
	}
}

// TestApiDocsServedWhenEnabled verifies that both docs endpoints serve the
// embedded Redoc page and OpenAPI spec when enable_api_docs is on.
func TestApiDocsServedWhenEnabled(t *testing.T) {
	router := docsRouter(t, true)

	require.Subset(t, registeredPaths(t, router), []string{"/api/docs", "/api/docs/swagger.yaml"})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/docs", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "text/html; charset=utf-8", rec.Header().Get("Content-Type"))
	require.Equal(t, redocHTML, rec.Body.Bytes())

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/docs/swagger.yaml", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/x-yaml", rec.Header().Get("Content-Type"))
	require.Equal(t, swaggerSpec, rec.Body.Bytes())
}

// TestApiDocsDisabledByDefault verifies that a config without enable_api_docs
// leaves the docs off, and that the flag is read from that JSON key.
func TestApiDocsDisabledByDefault(t *testing.T) {
	var config Config
	require.NoError(t, json.Unmarshal([]byte(`{"server_config":{"host":"0.0.0.0","port":8080}}`), &config))
	require.False(t, config.ServerConfig.EnableApiDocs)

	require.NoError(t, json.Unmarshal([]byte(`{"server_config":{"enable_api_docs":true}}`), &config))
	require.True(t, config.ServerConfig.EnableApiDocs)
}
