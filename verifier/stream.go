package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"image/jpeg"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/gorilla/websocket"

	"go-passport-issuer/analytics"
)

// Wire messages of the stream protocol.

type wsHello struct {
	Type  string `json:"type"`
	Token string `json:"token"`
}

type wsReady struct {
	Type      string `json:"type"`
	MaxFrames int    `json:"max_frames"`
	MaxWidth  int    `json:"max_width"`
	FPS       int    `json:"fps"`
}

type wsState struct {
	Type  string `json:"type"`
	Seq   uint32 `json:"seq"`
	State string `json:"state"`
}

type wsResult struct {
	Type     string   `json:"type"`
	State    string   `json:"state"`
	Passed   *bool    `json:"passed,omitempty"`
	Distance *float64 `json:"distance,omitempty"`
}

type wsError struct {
	Type string `json:"type"`
	Code string `json:"code"`
}

const (
	codeUnauthorized     = "unauthorized"
	codeExpired          = "expired"
	codeAlreadyStreaming = "already_streaming"
	codeTimeout          = "timeout"
	codeTooManyFrames    = "too_many_frames"
	codeFrameTooLarge    = "frame_too_large"
	codeBadFrame         = "bad_frame"
	// codeInternal is not in the plan's list: the verifier itself failed (no
	// worker, store down, portrait held by another replica). The wallet
	// treats it like any other error and starts a new session.
	codeInternal = "internal"
)

// stateInterval paces the state messages: "at most a few per second".
const stateInterval = 500 * time.Millisecond

// frameConn is the slice of *websocket.Conn the stream uses. Tests drive the
// handler through a scripted implementation, which makes frame pacing and
// timeouts deterministic without sleeping.
type frameConn interface {
	ReadMessage() (messageType int, p []byte, err error)
	WriteMessage(messageType int, data []byte) error
	SetReadDeadline(t time.Time) error
	Close() error
}

// streamer runs the WebSocket protocol for one session per call.
type streamer struct {
	cfg       Config
	store     Store
	portraits *portraitBox
	workers   WorkerFactory
	recorder  analytics.Recorder
	now       func() time.Time
	log       *slog.Logger
}

// serve handles one connection from hello to close.
func (s *streamer) serve(ctx context.Context, id string, conn frameConn) {
	defer func() { _ = conn.Close() }()
	sess, portrait, ok := s.handshake(ctx, id, conn)
	if !ok {
		return
	}
	s.run(ctx, sess, portrait, conn)
}

// handshake authenticates the first message and claims the session. It
// returns false after sending the error message; on true the session is
// streaming in the store and the portrait is in hand.
func (s *streamer) handshake(ctx context.Context, id string, conn frameConn) (Session, string, bool) {
	log := s.log.With("face_session_id", id)
	// Socket deadlines use the real clock; s.now (injectable in tests) drives
	// the protocol's own decisions.
	_ = conn.SetReadDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	mt, p, err := conn.ReadMessage()
	if err != nil {
		log.Info("stream closed before hello", "err", err)
		return Session{}, "", false
	}
	var hello wsHello
	if mt != websocket.TextMessage || json.Unmarshal(p, &hello) != nil || hello.Type != "hello" || hello.Token == "" {
		return s.refuse(conn, log, codeUnauthorized, "malformed hello")
	}

	sess, err := s.store.Get(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return s.refuse(conn, log, codeUnauthorized, "unknown session")
	}
	if err != nil {
		log.Error("store get", "err", err)
		return s.refuse(conn, log, codeInternal, "store unavailable")
	}
	sum := sha256.Sum256([]byte(hello.Token))
	if subtle.ConstantTimeCompare(sum[:], sess.TokenHash) != 1 {
		return s.refuse(conn, log, codeUnauthorized, "token mismatch")
	}
	now := s.now()
	switch sess.StatusAt(now) {
	case StatusPending:
	case StatusExpired:
		return s.refuse(conn, log, codeExpired, "session expired")
	default:
		return s.refuse(conn, log, codeAlreadyStreaming, "session already used")
	}
	// Looked up before the claim, so a miss leaves the session pending for a
	// retry that may reach the right replica.
	portrait, ok := s.portraits.Get(id)
	if !ok {
		log.Error("portrait not held by this replica; the stream must reach the replica that created the session")
		return s.refuse(conn, log, codeInternal, "portrait unavailable")
	}
	// A streaming record outlives the longest possible stream by TerminalTTL
	// so a crashed parent leaves a record that expires on its own.
	if err := s.store.Claim(ctx, id, now, s.cfg.Limits.MaxDuration+s.cfg.TerminalTTL); err != nil {
		if errors.Is(err, ErrNotPending) {
			return s.refuse(conn, log, codeAlreadyStreaming, "lost the claim")
		}
		log.Error("store claim", "err", err)
		return s.refuse(conn, log, codeInternal, "store unavailable")
	}
	s.portraits.Delete(id)
	sess.Status = StatusStreaming
	sess.StartedAt = now
	return sess, portrait, true
}

func (s *streamer) refuse(conn frameConn, log *slog.Logger, code, why string) (Session, string, bool) {
	log.Info("stream refused", "code", code, "reason", why)
	_ = writeJSONMessage(conn, wsError{Type: "error", Code: code})
	_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, code))
	return Session{}, "", false
}

// ending is how a stream stopped: either the engine decided (verdict set) or
// the stream was cut short with an error code, or the client vanished.
type ending struct {
	outcome string // analytics outcome
	decided bool
	verdict Verdict
	code    string // error code to send when !decided
	silent  bool   // nothing can be sent: the client is gone
}

type streamStats struct {
	frames   int
	dropped  int
	perFrame time.Duration
	// Where the per-frame time goes, summed over processed frames: the
	// worker's JPEG decode and engine run, the rest of the round trip to the
	// worker (pipe, scheduling), and the wait for the next frame to process
	// (network and the app's own pace). first holds frame 1 alone, which
	// carries the engine's lazy model loading.
	decode, run, pipe, idle time.Duration
	first                   frameTiming
}

type frameTiming struct {
	decode, run, pipe time.Duration
}

// timingAttrs summarises the breakdown for the stream ended log line.
func (st streamStats) timingAttrs() []any {
	if st.frames == 0 {
		return nil
	}
	n := float64(st.frames)
	return []any{
		"avg_decode_ms", ms(st.decode) / n,
		"avg_run_ms", ms(st.run) / n,
		"avg_pipe_ms", ms(st.pipe) / n,
		"avg_idle_ms", ms(st.idle) / n,
		"first_decode_ms", ms(st.first.decode),
		"first_run_ms", ms(st.first.run),
		"first_pipe_ms", ms(st.first.pipe),
	}
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// run streams frames to a worker and writes the terminal state everywhere it
// belongs: the connection, the store and the recorder.
func (s *streamer) run(ctx context.Context, sess Session, portrait string, conn frameConn) {
	log := s.log.With("face_session_id", sess.ID)
	var st streamStats
	e := s.stream(ctx, &sess, portrait, conn, &st, log)

	sess.EndedAt = s.now()
	sess.Frames = st.frames
	var msg any
	switch {
	case e.decided && e.verdict.State == StateCompleted:
		// The verdict is ours: the engine only measures.
		passed := e.verdict.Distance <= s.cfg.DistanceThreshold
		distance := e.verdict.Distance
		sess.Status = StatusCompleted
		sess.Passed = &passed
		sess.Distance = &distance
		msg = wsResult{Type: "result", State: "completed", Passed: &passed, Distance: &distance}
	case e.decided:
		sess.Status = StatusFailed
		msg = wsResult{Type: "result", State: "failed"}
	default:
		sess.Status = StatusFailed
		if !e.silent {
			msg = wsError{Type: "error", Code: e.code}
		}
	}
	if msg != nil {
		_ = writeJSONMessage(conn, msg)
		_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	}

	// The client's context may be gone; the record and the recording must
	// still be written.
	bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := s.store.Finish(bg, sess, s.cfg.TerminalTTL); err != nil {
		log.Error("store finish", "err", err)
	}
	s.recorder.Record(bg, s.event(sess, e, st))
	attrs := []any{"outcome", e.outcome, "code", e.code, "status", sess.Status,
		"passed", sess.Passed != nil && *sess.Passed, "frames", st.frames, "dropped", st.dropped, "duration_ms", sess.DurationMs()}
	log.Info("stream ended", append(attrs, st.timingAttrs()...)...)
}

func (s *streamer) event(sess Session, e ending, st streamStats) analytics.Record {
	ev := analytics.Record{
		Kind:         analytics.KindIrisSession,
		Method:       analytics.MethodIris,
		DocumentType: sess.DocumentType,
		Outcome:      e.outcome,
		DurationMs:   analytics.Int64(sess.DurationMs()),
		Frames:       analytics.Int(st.frames),
	}
	if st.frames > 0 {
		ev.PerFrameMs = analytics.Float64(float64(st.perFrame.Microseconds()) / 1000 / float64(st.frames))
	}
	if e.decided && e.verdict.State == StateCompleted {
		ev.Score = analytics.Float64(e.verdict.Distance)
		ev.ScoreKind = analytics.ScoreIrisDistance
	}
	return ev
}

// record adds one processed frame to the breakdown. The pipe share is what
// the round trip spent outside the worker's own decode and run.
func (st *streamStats) record(roundtrip, idle time.Duration, v Verdict) {
	pipe := max(roundtrip-v.DecodeTime-v.RunTime, 0)
	st.decode += v.DecodeTime
	st.run += v.RunTime
	st.pipe += pipe
	st.idle += idle
	if st.frames == 1 {
		st.first = frameTiming{decode: v.DecodeTime, run: v.RunTime, pipe: pipe}
	}
}

func decided(v Verdict) ending {
	outcome := analytics.OutcomeFailed
	if v.State == StateCompleted {
		outcome = analytics.OutcomeCompleted
	}
	return ending{outcome: outcome, decided: true, verdict: v}
}

func cut(outcome, code string) ending { return ending{outcome: outcome, code: code} }

// stream is the frame loop. It returns as soon as the session's ending is
// known and leaves all writing of that ending to run.
func (s *streamer) stream(ctx context.Context, sess *Session, portrait string, conn frameConn, st *streamStats, log *slog.Logger) ending {
	ready := wsReady{Type: "ready", MaxFrames: s.cfg.Limits.MaxFrames, MaxWidth: s.cfg.Limits.MaxWidth, FPS: s.cfg.Limits.FPS}
	if err := writeJSONMessage(conn, ready); err != nil {
		return ending{outcome: analytics.OutcomeAbandoned, silent: true}
	}
	worker, err := s.workers(ctx)
	if err != nil {
		log.Error("start worker", "err", err)
		return cut(analytics.OutcomeAbandoned, codeInternal)
	}
	defer func() { _ = worker.Close() }()

	v, err := worker.SetPortrait(ctx, portrait)
	if err != nil {
		// The portrait was validated at creation, so a rejection here is a
		// verifier problem, not a client one.
		log.Error("set portrait", "err", err)
		return cut(analytics.OutcomeAbandoned, codeInternal)
	}
	if v.State.Terminal() {
		return decided(v)
	}

	interval := time.Second / time.Duration(s.cfg.Limits.FPS)
	deadline := sess.StartedAt.Add(s.cfg.Limits.MaxDuration)
	_ = conn.SetReadDeadline(time.Now().Add(s.cfg.Limits.MaxDuration))
	var lastAccepted, lastState time.Time
	// lastDone is when the worker last answered: the gap from there to the
	// next processed frame is time the verifier sat idle.
	lastDone := s.now()
	for {
		mt, p, err := conn.ReadMessage()
		now := s.now()
		if err != nil {
			switch {
			case errors.Is(err, websocket.ErrReadLimit):
				return cut(analytics.OutcomeAbandoned, codeFrameTooLarge)
			case isTimeout(err):
				return cut(analytics.OutcomeTimeout, codeTimeout)
			}
			log.Info("client disconnected", "err", err)
			return ending{outcome: analytics.OutcomeAbandoned, silent: true}
		}
		if !now.Before(deadline) {
			return cut(analytics.OutcomeTimeout, codeTimeout)
		}
		if mt != websocket.BinaryMessage {
			return cut(analytics.OutcomeAbandoned, codeBadFrame)
		}
		hdr, jpegBytes, err := parseFrame(p)
		if err != nil {
			log.Info("bad frame", "err", err)
			return cut(analytics.OutcomeAbandoned, codeBadFrame)
		}
		if int64(len(jpegBytes)) > s.cfg.Limits.MaxFrameBytes {
			return cut(analytics.OutcomeAbandoned, codeFrameTooLarge)
		}
		// Pacing by arrival: the server clock, not the client's ts_ms, so a
		// client cannot push more work through by stamping its frames.
		if !lastAccepted.IsZero() && now.Sub(lastAccepted) < interval {
			st.dropped++
			continue
		}
		// DecodeConfig reads only the JPEG header; the full decode happens in
		// the worker.
		dims, err := jpeg.DecodeConfig(bytes.NewReader(jpegBytes))
		if err != nil {
			log.Info("bad frame", "seq", hdr.Seq, "err", err)
			return cut(analytics.OutcomeAbandoned, codeBadFrame)
		}
		if dims.Width > s.cfg.Limits.MaxWidth || dims.Height > s.cfg.Limits.MaxWidth {
			return cut(analytics.OutcomeAbandoned, codeFrameTooLarge)
		}
		if st.frames >= s.cfg.Limits.MaxFrames {
			// The engine had its full frame budget and did not decide: the
			// same kind of ending as running out of time.
			return cut(analytics.OutcomeTimeout, codeTooManyFrames)
		}
		lastAccepted = now
		st.frames++
		s.dumpFrame(sess.ID, st.frames, hdr, dims.Width, dims.Height, jpegBytes, log)

		v, err := worker.Frame(ctx, hdr.Orientation, jpegBytes)
		done := s.now()
		st.perFrame += done.Sub(now)
		if err == nil {
			st.record(done.Sub(now), now.Sub(lastDone), v)
			log.Debug("frame timing", "seq", hdr.Seq, "n", st.frames, "decode_ms", ms(v.DecodeTime), "run_ms", ms(v.RunTime),
				"roundtrip_ms", ms(done.Sub(now)), "idle_ms", ms(now.Sub(lastDone)), "state", v.State.String(), "distance", v.Distance)
		}
		lastDone = done
		if err != nil {
			var rejected *RejectedError
			if errors.As(err, &rejected) {
				log.Info("frame rejected", "seq", hdr.Seq, "reason", rejected.Reason)
				return cut(analytics.OutcomeAbandoned, codeBadFrame)
			}
			log.Error("worker call", "seq", hdr.Seq, "err", err)
			return cut(analytics.OutcomeAbandoned, codeInternal)
		}
		if v.State.Terminal() {
			return decided(v)
		}
		if lastState.IsZero() || now.Sub(lastState) >= stateInterval {
			lastState = now
			if err := writeJSONMessage(conn, wsState{Type: "state", Seq: hdr.Seq, State: "initiated"}); err != nil {
				return ending{outcome: analytics.OutcomeAbandoned, silent: true}
			}
		}
	}
}

// dumpFrame writes processed frame n of a session to the debug frame
// directory, when one is configured and n is within the debug frame count.
// The name carries what the engine is told about the frame, so an upside-down
// face can be told apart from a wrong orientation byte. Failures are logged
// and never affect the stream.
func (s *streamer) dumpFrame(id string, n int, hdr FrameHeader, width, height int, jpegBytes []byte, log *slog.Logger) {
	if s.cfg.DebugFrameDir == "" || n > s.cfg.DebugFrameCount {
		return
	}
	dir := filepath.Join(s.cfg.DebugFrameDir, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Warn("debug frame dump", "err", err)
		return
	}
	name := fmt.Sprintf("%03d_seq%d_ts%d_o%d_%dx%d.jpg", n, hdr.Seq, hdr.TsMs, hdr.Orientation, width, height)
	if err := os.WriteFile(filepath.Join(dir, name), jpegBytes, 0o600); err != nil {
		log.Warn("debug frame dump", "err", err)
	}
}

func writeJSONMessage(conn frameConn, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return conn.WriteMessage(websocket.TextMessage, b)
}

func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
