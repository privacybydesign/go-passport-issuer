package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
