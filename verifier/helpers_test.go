package main

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"

	"go-passport-issuer/analytics"
)

// fakeClock is the streamer's and store's clock in tests, so pacing, limits
// and TTLs are exercised without sleeping.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// testJPEG encodes a w×h JPEG filled with one colour; distinct colours give
// distinct bytes, which lets tests tell frames apart.
func testJPEG(t *testing.T, w, h int, c color.Color) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, c)
		}
	}
	var buf bytes.Buffer
	require.NoError(t, jpeg.Encode(&buf, img, &jpeg.Options{Quality: 80}))
	return buf.Bytes()
}

// frameJPEG is a small camera-like frame whose bytes depend on seq.
func frameJPEG(t *testing.T, seq int) []byte {
	t.Helper()
	return testJPEG(t, 32, 24, color.RGBA{R: uint8(seq * 7), G: uint8(seq * 13), B: 128, A: 255})
}

var initiated = Verdict{State: StateInitiated}

func completed(distance float64) Verdict { return Verdict{State: StateCompleted, Distance: distance} }

// fakeWorker stands in for the worker subprocess. It answers SetPortrait with
// portraitVerdict and the i-th frame with verdicts[i], repeating the last
// verdict past the end and answering INITIATED when the list is empty.
type fakeWorker struct {
	mu              sync.Mutex
	portraitVerdict Verdict
	portraitErr     error
	verdicts        []Verdict
	frameErr        error // returned for every frame when set
	spawnErr        error

	started      int
	portrait     string
	frames       [][]byte
	orientations []uint8
	closed       int
}

func (f *fakeWorker) factory() WorkerFactory {
	return func(context.Context) (Worker, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.spawnErr != nil {
			return nil, f.spawnErr
		}
		f.started++
		return f, nil
	}
}

func (f *fakeWorker) SetPortrait(_ context.Context, portrait string) (Verdict, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.portrait = portrait
	return f.portraitVerdict, f.portraitErr
}

func (f *fakeWorker) Frame(_ context.Context, orientation uint8, jpeg []byte) (Verdict, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.frames = append(f.frames, bytes.Clone(jpeg))
	f.orientations = append(f.orientations, orientation)
	if f.frameErr != nil {
		return Verdict{}, f.frameErr
	}
	if len(f.verdicts) == 0 {
		return initiated, nil
	}
	i := min(len(f.frames)-1, len(f.verdicts)-1)
	return f.verdicts[i], nil
}

func (f *fakeWorker) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed++
	return nil
}

type fakeRecorder struct {
	mu     sync.Mutex
	events []analytics.Record
}

func (r *fakeRecorder) Record(_ context.Context, e analytics.Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *fakeRecorder) single(t *testing.T) analytics.Record {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	require.Len(t, r.events, 1)
	return r.events[0]
}

// scriptConn feeds the streamer a fixed sequence of reads. A step may move
// the fake clock before returning its message, which is how the tests place
// frames in time without sleeping.
type step func() (int, []byte, error)

type written struct {
	mt   int
	data []byte
}

type scriptConn struct {
	steps  []step
	writes []written
	closed bool
	// onWrite, when set, runs before each write is recorded.
	onWrite func(mt int, data []byte)
}

func (c *scriptConn) ReadMessage() (int, []byte, error) {
	if len(c.steps) == 0 {
		return 0, nil, io.EOF
	}
	s := c.steps[0]
	c.steps = c.steps[1:]
	return s()
}

func (c *scriptConn) WriteMessage(mt int, data []byte) error {
	if c.onWrite != nil {
		c.onWrite(mt, data)
	}
	c.writes = append(c.writes, written{mt: mt, data: bytes.Clone(data)})
	return nil
}

func (c *scriptConn) SetReadDeadline(time.Time) error { return nil }

func (c *scriptConn) Close() error {
	c.closed = true
	return nil
}

// texts decodes every text message written, in order.
func (c *scriptConn) texts(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, w := range c.writes {
		if w.mt != websocket.TextMessage {
			continue
		}
		var m map[string]any
		require.NoError(t, json.Unmarshal(w.data, &m), "message: %s", w.data)
		out = append(out, m)
	}
	return out
}

func (c *scriptConn) closeFrames() int {
	n := 0
	for _, w := range c.writes {
		if w.mt == websocket.CloseMessage {
			n++
		}
	}
	return n
}

// last is the final text message, which is where the terminal message lands.
func (c *scriptConn) last(t *testing.T) map[string]any {
	t.Helper()
	ts := c.texts(t)
	require.NotEmpty(t, ts)
	return ts[len(ts)-1]
}

func textStep(v any) step {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return func() (int, []byte, error) { return websocket.TextMessage, b, nil }
}

func helloStep(token string) step { return textStep(wsHello{Type: "hello", Token: token}) }

func binaryStep(b []byte) step {
	return func() (int, []byte, error) { return websocket.BinaryMessage, b, nil }
}

func frameStep(seq uint32, jpeg []byte) step {
	return binaryStep(FrameHeader{Seq: seq, TsMs: seq * 66, Width: 32, Height: 24}.encode(jpeg))
}

// after moves the clock by d, then performs next.
func after(clock *fakeClock, d time.Duration, next step) step {
	return func() (int, []byte, error) {
		clock.Advance(d)
		return next()
	}
}

func errStep(err error) step {
	return func() (int, []byte, error) { return 0, nil, err }
}

// fixture wires a server with the in-memory store, a fake worker, a fake
// recorder and a fake clock.
type fixture struct {
	t      *testing.T
	cfg    Config
	clock  *fakeClock
	store  *memoryStore
	rec    *fakeRecorder
	worker *fakeWorker
	srv    *server
}

func newFixture(t *testing.T, worker *fakeWorker, mutate func(*Config)) *fixture {
	t.Helper()
	cfg := defaultConfig()
	if mutate != nil {
		mutate(&cfg)
	}
	clock := newFakeClock()
	store := newMemoryStore(clock.Now)
	rec := &fakeRecorder{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := newServer(cfg, store, worker.factory(), rec, clock.Now, logger)
	return &fixture{t: t, cfg: cfg, clock: clock, store: store, rec: rec, worker: worker, srv: srv}
}

var testPortrait = []byte("not really an image, but the verifier does not look inside")

// createSession goes through the internal API, as the issuer would.
func (f *fixture) createSession() (id, token string) {
	f.t.Helper()
	resp, body := f.createSessionRaw(createSessionRequest{
		Portrait:       base64Std(testPortrait),
		PortraitSHA256: sha256Hex(testPortrait),
		DocumentType:   "passport",
	})
	require.Equal(f.t, http.StatusOK, resp.Code, body.String())
	var cr createSessionResponse
	require.NoError(f.t, json.Unmarshal(body.Bytes(), &cr))
	return cr.FaceSessionID, cr.Token
}

func (f *fixture) createSessionRaw(req any) (*httptest.ResponseRecorder, *bytes.Buffer) {
	f.t.Helper()
	b, err := json.Marshal(req)
	require.NoError(f.t, err)
	r := httptest.NewRequest(http.MethodPost, "/internal/sessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	f.srv.handler().ServeHTTP(w, r)
	return w, w.Body
}

func (f *fixture) getSession(id string) (int, sessionResponse) {
	f.t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/internal/sessions/"+id, nil)
	w := httptest.NewRecorder()
	f.srv.handler().ServeHTTP(w, r)
	var sr sessionResponse
	if w.Code == http.StatusOK {
		require.NoError(f.t, json.Unmarshal(w.Body.Bytes(), &sr))
	}
	return w.Code, sr
}

func (f *fixture) deleteSession(id string) int {
	f.t.Helper()
	r := httptest.NewRequest(http.MethodDelete, "/internal/sessions/"+id, nil)
	w := httptest.NewRecorder()
	f.srv.handler().ServeHTTP(w, r)
	return w.Code
}

// stream runs the WebSocket protocol for id against the scripted reads and
// returns the connection for inspection.
func (f *fixture) stream(id string, steps ...step) *scriptConn {
	f.t.Helper()
	conn := &scriptConn{steps: steps}
	f.srv.streamer.serve(context.Background(), id, conn)
	require.True(f.t, conn.closed, "connection must be closed after serve")
	return conn
}

// streamFrames is the common script: hello, then n frames spaced one FPS
// interval apart so none is dropped.
func (f *fixture) streamFrames(id, token string, n int) *scriptConn {
	f.t.Helper()
	steps := []step{helloStep(token)}
	for i := 1; i <= n; i++ {
		s := frameStep(uint32(i), frameJPEG(f.t, i))
		if i > 1 {
			s = after(f.clock, time.Second/time.Duration(f.cfg.Limits.FPS), s)
		}
		steps = append(steps, s)
	}
	return f.stream(id, steps...)
}
