package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

// TestUnmatchedRoutesReturnNotFound verifies that this service is API-only:
// paths that are not registered routes get a 404 and are not swallowed by a
// catch-all handler that used to serve the SPA's index.html.
func TestUnmatchedRoutesReturnNotFound(t *testing.T) {
	srv, err := NewServer(&ServerState{}, ServerConfig{})
	require.NoError(t, err)

	router, ok := srv.server.Handler.(*mux.Router)
	require.True(t, ok, "server handler should be a mux router")

	for _, path := range []string{"/", "/index.html", "/some/spa/route", "/assets/main.js"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)

			// No route may match, otherwise a handler (such as the removed SPA
			// catch-all) is still claiming these paths.
			var match mux.RouteMatch
			require.False(t, router.Match(req, &match), "no route should match %s", path)
			require.ErrorIs(t, match.MatchErr, mux.ErrNotFound)

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			require.Equal(t, http.StatusNotFound, rec.Code)
		})
	}
}

// TestRegisteredRoutesStillMatch guards against removing too much: the API
// routes must keep matching now that the catch-all is gone.
func TestRegisteredRoutesStillMatch(t *testing.T) {
	srv, err := NewServer(&ServerState{}, ServerConfig{})
	require.NoError(t, err)

	router, ok := srv.server.Handler.(*mux.Router)
	require.True(t, ok, "server handler should be a mux router")

	for _, path := range []string{
		"/api/health",
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
