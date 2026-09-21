package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

func TestInternalAPICreateGetDelete(t *testing.T) {
	f := newFixture(t, &fakeWorker{}, nil)
	resp, body := f.createSessionRaw(createSessionRequest{
		Portrait:       base64Std(testPortrait),
		PortraitSHA256: strings.ToUpper(sha256Hex(testPortrait)),
		DocumentType:   "id_card",
	})
	require.Equal(t, http.StatusOK, resp.Code, body.String())
	var cr createSessionResponse
	require.NoError(t, json.Unmarshal(body.Bytes(), &cr))
	require.Regexp(t, `^fs_[0-9a-f]{32}$`, cr.FaceSessionID)
	tokenBytes, err := base64.RawURLEncoding.DecodeString(cr.Token)
	require.NoError(t, err)
	require.Len(t, tokenBytes, 32)
	expires, err := time.Parse(time.RFC3339, cr.ExpiresAt)
	require.NoError(t, err)
	require.True(t, expires.Equal(f.clock.Now().Add(10*time.Minute)))
	require.Equal(t, "2026-09-21T12:10:00Z", cr.ExpiresAt, "RFC 3339, UTC, whole seconds")

	code, sr := f.getSession(cr.FaceSessionID)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, sessionResponse{Status: StatusPending, PortraitSHA256: sha256Hex(testPortrait)}, sr, "hash is stored lower-case; no verdict fields yet")

	// Only the hash of the token is stored.
	stored, err := f.store.Get(context.Background(), cr.FaceSessionID)
	require.NoError(t, err)
	require.NotContains(t, string(stored.TokenHash), cr.Token)
	require.Len(t, stored.TokenHash, 32)

	require.Equal(t, http.StatusNoContent, f.deleteSession(cr.FaceSessionID))
	require.Equal(t, http.StatusNoContent, f.deleteSession(cr.FaceSessionID), "idempotent")
	code, _ = f.getSession(cr.FaceSessionID)
	require.Equal(t, http.StatusNotFound, code)
	_, held := f.srv.portraits.Get(cr.FaceSessionID)
	require.False(t, held, "delete also drops the portrait")
}

// The issuer decodes exactly these names; pin the JSON shape.
func TestCreateSessionResponseShape(t *testing.T) {
	f := newFixture(t, &fakeWorker{}, nil)
	_, body := f.createSessionRaw(createSessionRequest{
		Portrait: base64Std(testPortrait), PortraitSHA256: sha256Hex(testPortrait), DocumentType: "passport",
	})
	var raw map[string]any
	require.NoError(t, json.Unmarshal(body.Bytes(), &raw))
	require.ElementsMatch(t, []string{"face_session_id", "token", "expires_at"}, keys(raw))
}

func TestGetSessionResponseShape(t *testing.T) {
	f := newFixture(t, &fakeWorker{verdicts: []Verdict{completed(0.2)}}, nil)
	id, token := f.createSession()

	r := httptest.NewRequest(http.MethodGet, "/internal/sessions/"+id, nil)
	w := httptest.NewRecorder()
	f.srv.handler().ServeHTTP(w, r)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
	require.ElementsMatch(t, []string{"status", "portrait_sha256", "frames", "duration_ms"}, keys(raw), "no passed or distance before completion")

	f.streamFrames(id, token, 1)
	w = httptest.NewRecorder()
	f.srv.handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/internal/sessions/"+id, nil))
	raw = nil
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
	require.ElementsMatch(t, []string{"status", "passed", "distance", "portrait_sha256", "frames", "duration_ms"}, keys(raw))
	require.Equal(t, "completed", raw["status"])
	require.Equal(t, true, raw["passed"])
	require.Equal(t, 0.2, raw["distance"])
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestCreateSessionRejectsBadRequests(t *testing.T) {
	good := createSessionRequest{Portrait: base64Std(testPortrait), PortraitSHA256: sha256Hex(testPortrait), DocumentType: "passport"}
	cases := map[string]struct {
		mutate func(*createSessionRequest)
		want   string
	}{
		"hash mismatch":    {func(r *createSessionRequest) { r.PortraitSHA256 = sha256Hex([]byte("other")) }, "portrait_sha256"},
		"missing hash":     {func(r *createSessionRequest) { r.PortraitSHA256 = "" }, "portrait_sha256"},
		"not base64":       {func(r *createSessionRequest) { r.Portrait = "%%%" }, "base64"},
		"empty portrait":   {func(r *createSessionRequest) { r.Portrait = "" }, "base64"},
		"unknown doc type": {func(r *createSessionRequest) { r.DocumentType = "visa" }, "document_type"},
		"missing doc type": {func(r *createSessionRequest) { r.DocumentType = "" }, "document_type"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, &fakeWorker{}, nil)
			req := good
			tc.mutate(&req)
			resp, body := f.createSessionRaw(req)
			require.Equal(t, http.StatusBadRequest, resp.Code)
			require.Contains(t, body.String(), tc.want)
		})
	}
	t.Run("invalid json", func(t *testing.T) {
		f := newFixture(t, &fakeWorker{}, nil)
		r := httptest.NewRequest(http.MethodPost, "/internal/sessions", strings.NewReader("{"))
		w := httptest.NewRecorder()
		f.srv.handler().ServeHTTP(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// Unpadded base64 from the issuer is accepted; the engine still gets padded.
func TestCreateSessionAcceptsRawBase64(t *testing.T) {
	f := newFixture(t, &fakeWorker{}, nil)
	resp, body := f.createSessionRaw(createSessionRequest{
		Portrait:       base64.RawStdEncoding.EncodeToString(testPortrait),
		PortraitSHA256: sha256Hex(testPortrait),
		DocumentType:   "passport",
	})
	require.Equal(t, http.StatusOK, resp.Code, body.String())
	var cr createSessionResponse
	require.NoError(t, json.Unmarshal(body.Bytes(), &cr))
	p, _ := f.srv.portraits.Get(cr.FaceSessionID)
	require.Equal(t, base64Std(testPortrait), p)
}

func TestGetSessionExpiresThenDisappears(t *testing.T) {
	f := newFixture(t, &fakeWorker{}, nil)
	id, _ := f.createSession()

	f.clock.Advance(f.cfg.PendingTTL)
	code, sr := f.getSession(id)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, StatusExpired, sr.Status, "readable as expired for the issuer")

	f.clock.Advance(f.cfg.TerminalTTL)
	code, _ = f.getSession(id)
	require.Equal(t, http.StatusNotFound, code)
}

func TestHealthz(t *testing.T) {
	f := newFixture(t, &fakeWorker{}, nil)
	w := httptest.NewRecorder()
	f.srv.handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	require.Equal(t, http.StatusOK, w.Code)
}

type failingPingStore struct{ Store }

func (failingPingStore) Ping(context.Context) error { return errors.New("redis down") }

func TestReadyz(t *testing.T) {
	f := newFixture(t, &fakeWorker{}, nil)
	f.srv.workerCheck = nil
	w := httptest.NewRecorder()
	f.srv.handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"public_stream_url"`)

	f.srv.store = failingPingStore{f.store}
	w = httptest.NewRecorder()
	f.srv.handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	require.Equal(t, http.StatusServiceUnavailable, w.Code)

	f.srv.store = f.store
	f.srv.workerCheck = func(context.Context) error { return errors.New("no worker") }
	w = httptest.NewRecorder()
	f.srv.handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestInternalRoutesRejectOtherMethods(t *testing.T) {
	f := newFixture(t, &fakeWorker{}, nil)
	w := httptest.NewRecorder()
	f.srv.handler().ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/internal/sessions/fs_x", nil))
	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// --- over a real WebSocket ----------------------------------------------

func dial(t *testing.T, srv *httptest.Server, id string) *websocket.Conn {
	t.Helper()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/stream/" + id
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	return conn
}

func readJSON(t *testing.T, conn *websocket.Conn) map[string]any {
	t.Helper()
	mt, p, err := conn.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, websocket.TextMessage, mt)
	var m map[string]any
	require.NoError(t, json.Unmarshal(p, &m))
	return m
}

func TestStreamOverWebSocket(t *testing.T) {
	worker := &fakeWorker{verdicts: []Verdict{initiated, completed(0.33)}}
	f := newFixture(t, worker, nil)
	srv := httptest.NewServer(f.srv.handler())
	defer srv.Close()
	id, token := f.createSession()

	conn := dial(t, srv, id)
	require.NoError(t, conn.WriteJSON(wsHello{Type: "hello", Token: token}))
	require.Equal(t, "ready", readJSON(t, conn)["type"])

	require.NoError(t, conn.WriteMessage(websocket.BinaryMessage, FrameHeader{Seq: 1}.encode(frameJPEG(t, 1))))
	require.Equal(t, "state", readJSON(t, conn)["type"])

	f.clock.Advance(time.Second)
	require.NoError(t, conn.WriteMessage(websocket.BinaryMessage, FrameHeader{Seq: 2, Orientation: 1}.encode(frameJPEG(t, 2))))
	result := readJSON(t, conn)
	require.Equal(t, map[string]any{"type": "result", "state": "completed", "passed": true, "distance": 0.33}, result)

	_, _, err := conn.ReadMessage()
	var closeErr *websocket.CloseError
	require.ErrorAs(t, err, &closeErr)
	require.Equal(t, websocket.CloseNormalClosure, closeErr.Code)

	require.Equal(t, []uint8{0, 1}, worker.orientations)
	require.Eventually(t, func() bool {
		_, sr := f.getSession(id)
		return sr.Status == StatusCompleted
	}, 5*time.Second, 10*time.Millisecond)
}

func TestStreamOverWebSocketUnauthorized(t *testing.T) {
	f := newFixture(t, &fakeWorker{}, nil)
	srv := httptest.NewServer(f.srv.handler())
	defer srv.Close()
	id, _ := f.createSession()

	conn := dial(t, srv, id)
	require.NoError(t, conn.WriteJSON(wsHello{Type: "hello", Token: "wrong"}))
	require.Equal(t, map[string]any{"type": "error", "code": "unauthorized"}, readJSON(t, conn))
	_, _, err := conn.ReadMessage()
	var closeErr *websocket.CloseError
	require.ErrorAs(t, err, &closeErr)
	require.Equal(t, websocket.ClosePolicyViolation, closeErr.Code)
}

// A message beyond the read limit is cut off by the WebSocket layer itself.
func TestStreamOverWebSocketReadLimit(t *testing.T) {
	f := newFixture(t, &fakeWorker{}, func(c *Config) { c.Limits.MaxFrameBytes = 100 })
	srv := httptest.NewServer(f.srv.handler())
	defer srv.Close()
	id, token := f.createSession()

	conn := dial(t, srv, id)
	require.NoError(t, conn.WriteJSON(wsHello{Type: "hello", Token: token}))
	require.Equal(t, "ready", readJSON(t, conn)["type"])
	require.NoError(t, conn.WriteMessage(websocket.BinaryMessage, FrameHeader{Seq: 1}.encode(make([]byte, 5000))))

	// Either our frame_too_large or the library's 1009 close; both end it.
	_, p, err := conn.ReadMessage()
	if err == nil {
		require.Contains(t, string(p), "frame_too_large")
	} else {
		var closeErr *websocket.CloseError
		require.ErrorAs(t, err, &closeErr)
	}
	require.Eventually(t, func() bool {
		_, sr := f.getSession(id)
		return sr.Status == StatusFailed
	}, 5*time.Second, 10*time.Millisecond)
}

func TestStreamRouteNeedsUpgrade(t *testing.T) {
	f := newFixture(t, &fakeWorker{}, nil)
	w := httptest.NewRecorder()
	f.srv.handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/stream/fs_x", nil))
	require.Equal(t, http.StatusBadRequest, w.Code)
}
