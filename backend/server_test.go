package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

// TestUnmatchedRoutesReturnNotFound verifies that this service is API-only:
// paths that are not registered routes get a 404 and are not swallowed by a
// catch-all handler such as the removed SPA handler, which served index.html.
// The docs are enabled here so the router carries every route it can, which
// makes the assertion about the paths and not about the configuration.
func TestUnmatchedRoutesReturnNotFound(t *testing.T) {
	router := docsRouter(t, true)

	for _, path := range []string{"/", "/index.html", "/some/spa/route", "/assets/main.js"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)

			// A catch-all (such as the removed SPA handler) matches and leaves
			// MatchErr nil, so asserting on MatchErr rejects one while still
			// allowing a custom NotFoundHandler.
			var match mux.RouteMatch
			router.Match(req, &match)
			require.ErrorIs(t, match.MatchErr, mux.ErrNotFound)

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			require.Equal(t, http.StatusNotFound, rec.Code)
		})
	}
}

// TestRegisteredRoutesStillMatch guards against removing too much: the API and
// app-association routes must keep matching now that the catch-all is gone.
func TestRegisteredRoutesStillMatch(t *testing.T) {
	router := docsRouter(t, true)

	for _, path := range []string{
		"/api/health",
		"/api/start-validation",
		"/api/verify-and-issue",
		"/api/issue-passport",
		"/api/issue-id-card",
		"/api/verify-passport",
		"/api/verify-driving-licence",
		"/api/issue-driving-licence",
		"/api/docs",
		"/api/docs/swagger.yaml",
		"/.well-known/apple-app-site-association",
		"/apple-app-site-association",
		"/.well-known/assetlinks.json",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			var match mux.RouteMatch
			require.True(t, router.Match(req, &match), "route %s should match", path)
		})
	}
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

		// The paths are not registered at all, so they behave like any other
		// unknown path. What matters is that the docs themselves are not served.
		require.Equal(t, http.StatusNotFound, rec.Code, "docs path %s should not be routed", path)
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
