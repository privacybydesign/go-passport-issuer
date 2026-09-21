package main

import (
	"context"
	"errors"
	"image/color"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go-passport-issuer/analytics"
)

func TestStreamCompletedWithinThresholdPasses(t *testing.T) {
	worker := &fakeWorker{verdicts: []Verdict{initiated, initiated, completed(0.41)}}
	f := newFixture(t, worker, nil)
	id, token := f.createSession()

	conn := f.streamFrames(id, token, 3)

	msgs := conn.texts(t)
	require.Equal(t, "ready", msgs[0]["type"])
	require.EqualValues(t, 900, msgs[0]["max_frames"])
	require.EqualValues(t, 640, msgs[0]["max_width"])
	require.EqualValues(t, 15, msgs[0]["fps"])
	require.Equal(t, map[string]any{"type": "state", "seq": float64(1), "state": "initiated"}, msgs[1])
	require.Equal(t, map[string]any{"type": "result", "state": "completed", "passed": true, "distance": 0.41}, conn.last(t))
	require.Equal(t, 1, conn.closeFrames())

	require.Equal(t, base64Std(testPortrait), worker.portrait)
	require.Len(t, worker.frames, 3)
	require.Equal(t, 1, worker.closed, "the worker is killed at the terminal state")

	code, sr := f.getSession(id)
	require.Equal(t, 200, code)
	require.Equal(t, StatusCompleted, sr.Status)
	require.True(t, *sr.Passed)
	require.Equal(t, 0.41, *sr.Distance)
	require.Equal(t, 3, sr.Frames)
	require.EqualValues(t, (2 * time.Second / 15).Milliseconds(), sr.DurationMs, "two FPS intervals on the fake clock")

	ev := f.rec.single(t)
	require.Equal(t, analytics.KindIrisSession, ev.Kind)
	require.Equal(t, analytics.MethodIris, ev.Method)
	require.Equal(t, "passport", ev.DocumentType)
	require.Equal(t, analytics.OutcomeCompleted, ev.Outcome)
	require.Equal(t, 0.41, *ev.Score)
	require.Equal(t, analytics.ScoreIrisDistance, ev.ScoreKind)
	require.Equal(t, 3, *ev.Frames)
	require.NotNil(t, ev.DurationMs)
	require.NotNil(t, ev.PerFrameMs)
}

func TestStreamCompletedAboveThresholdDoesNotPass(t *testing.T) {
	worker := &fakeWorker{verdicts: []Verdict{completed(0.9)}}
	f := newFixture(t, worker, nil)
	id, token := f.createSession()

	conn := f.streamFrames(id, token, 1)
	require.Equal(t, map[string]any{"type": "result", "state": "completed", "passed": false, "distance": 0.9}, conn.last(t))

	_, sr := f.getSession(id)
	require.Equal(t, StatusCompleted, sr.Status)
	require.False(t, *sr.Passed)
	require.Equal(t, analytics.OutcomeCompleted, f.rec.single(t).Outcome, "the engine completed; the verdict is ours")
}

func TestStreamThresholdIsConfigurable(t *testing.T) {
	worker := &fakeWorker{verdicts: []Verdict{completed(0.9)}}
	f := newFixture(t, worker, func(c *Config) { c.DistanceThreshold = 1.0 })
	id, token := f.createSession()
	conn := f.streamFrames(id, token, 1)
	require.Equal(t, true, conn.last(t)["passed"])
}

func TestStreamEngineFailed(t *testing.T) {
	worker := &fakeWorker{verdicts: []Verdict{initiated, {State: StateFailed}}}
	f := newFixture(t, worker, nil)
	id, token := f.createSession()

	conn := f.streamFrames(id, token, 2)
	require.Equal(t, map[string]any{"type": "result", "state": "failed"}, conn.last(t))

	_, sr := f.getSession(id)
	require.Equal(t, StatusFailed, sr.Status)
	require.Nil(t, sr.Passed, "passed and distance appear only once the engine completed")
	require.Nil(t, sr.Distance)
	ev := f.rec.single(t)
	require.Equal(t, analytics.OutcomeFailed, ev.Outcome)
	require.Nil(t, ev.Score)
}

// A portrait the engine cannot find a face in fails the session before any
// frame; the ready message has already gone out by then.
func TestStreamPortraitWithoutFaceFailsAtOnce(t *testing.T) {
	worker := &fakeWorker{portraitVerdict: Verdict{State: StateFailed}}
	f := newFixture(t, worker, nil)
	id, token := f.createSession()

	conn := f.stream(id, helloStep(token))
	msgs := conn.texts(t)
	require.Len(t, msgs, 2)
	require.Equal(t, "ready", msgs[0]["type"])
	require.Equal(t, map[string]any{"type": "result", "state": "failed"}, msgs[1])
	_, sr := f.getSession(id)
	require.Equal(t, StatusFailed, sr.Status)
	require.Equal(t, 0, sr.Frames)
}

func TestStreamDropsFramesFasterThanFPS(t *testing.T) {
	worker := &fakeWorker{}
	f := newFixture(t, worker, nil)
	id, token := f.createSession()
	interval := time.Second / 15

	j := func(i int) []byte { return frameJPEG(t, i) }
	f.stream(id,
		helloStep(token),
		frameStep(1, j(1)),
		frameStep(2, j(2)), // same instant: dropped
		after(f.clock, interval-time.Millisecond, frameStep(3, j(3))), // 1ms early: dropped
		after(f.clock, time.Millisecond, frameStep(4, j(4))),          // exactly one interval after frame 1
		after(f.clock, 10*time.Second, frameStep(5, j(5))),
		after(f.clock, time.Millisecond, frameStep(6, j(6))), // dropped
	)
	require.Equal(t, [][]byte{j(1), j(4), j(5)}, worker.frames)
	_, sr := f.getSession(id)
	require.Equal(t, 3, sr.Frames, "dropped frames are not counted")
}

func TestStreamTooManyFrames(t *testing.T) {
	worker := &fakeWorker{}
	f := newFixture(t, worker, func(c *Config) { c.Limits.MaxFrames = 2 })
	id, token := f.createSession()

	conn := f.streamFrames(id, token, 3)
	require.Equal(t, map[string]any{"type": "error", "code": "too_many_frames"}, conn.last(t))
	require.Len(t, worker.frames, 2, "the frame over budget is not processed")
	_, sr := f.getSession(id)
	require.Equal(t, StatusFailed, sr.Status)
	require.Equal(t, 2, sr.Frames)
	require.Equal(t, analytics.OutcomeTimeout, f.rec.single(t).Outcome)
}

func TestStreamFrameTooLarge(t *testing.T) {
	t.Run("dimensions", func(t *testing.T) {
		worker := &fakeWorker{}
		f := newFixture(t, worker, func(c *Config) { c.Limits.MaxWidth = 64 })
		id, token := f.createSession()
		big := testJPEG(t, 100, 20, color.Gray{Y: 128})
		conn := f.stream(id, helloStep(token), frameStep(1, big))
		require.Equal(t, map[string]any{"type": "error", "code": "frame_too_large"}, conn.last(t))
		require.Empty(t, worker.frames)
	})
	t.Run("bytes", func(t *testing.T) {
		worker := &fakeWorker{}
		f := newFixture(t, worker, func(c *Config) { c.Limits.MaxFrameBytes = 100 })
		id, token := f.createSession()
		conn := f.stream(id, helloStep(token), frameStep(1, frameJPEG(t, 1)))
		require.Equal(t, map[string]any{"type": "error", "code": "frame_too_large"}, conn.last(t))
		require.Empty(t, worker.frames)
	})
	t.Run("tall", func(t *testing.T) {
		worker := &fakeWorker{}
		f := newFixture(t, worker, func(c *Config) { c.Limits.MaxWidth = 64 })
		id, token := f.createSession()
		tall := testJPEG(t, 20, 100, color.Gray{Y: 128})
		conn := f.stream(id, helloStep(token), frameStep(1, tall))
		require.Equal(t, "frame_too_large", conn.last(t)["code"], "the limit is on the long side, whichever it is")
	})
}

func TestStreamBadFrame(t *testing.T) {
	cases := map[string]step{
		"short header": binaryStep([]byte{1, 2, 3}),
		"no jpeg":      binaryStep(FrameHeader{}.encode(nil)),
		"garbage jpeg": frameStep(1, []byte("not a jpeg at all")),
		"orientation":  binaryStep(FrameHeader{Orientation: 9}.encode([]byte("x"))),
		"text message": textStep(map[string]string{"type": "frame"}),
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			worker := &fakeWorker{}
			f := newFixture(t, worker, nil)
			id, token := f.createSession()
			conn := f.stream(id, helloStep(token), s)
			require.Equal(t, map[string]any{"type": "error", "code": "bad_frame"}, conn.last(t))
			require.Equal(t, 1, conn.closeFrames())
			_, sr := f.getSession(id)
			require.Equal(t, StatusFailed, sr.Status)
			require.Equal(t, analytics.OutcomeAbandoned, f.rec.single(t).Outcome)
		})
	}
}

// A frame the worker rejects (its decoder disagrees with our header check,
// or the engine refuses it) is a bad frame too.
func TestStreamWorkerRejectsFrame(t *testing.T) {
	worker := &fakeWorker{frameErr: &RejectedError{Reason: "run: returned -1"}}
	f := newFixture(t, worker, nil)
	id, token := f.createSession()
	conn := f.streamFrames(id, token, 1)
	require.Equal(t, map[string]any{"type": "error", "code": "bad_frame"}, conn.last(t))
}

func TestStreamTimeoutByClock(t *testing.T) {
	worker := &fakeWorker{}
	f := newFixture(t, worker, func(c *Config) { c.Limits.MaxDuration = 10 * time.Second })
	id, token := f.createSession()

	conn := f.stream(id,
		helloStep(token),
		frameStep(1, frameJPEG(t, 1)),
		after(f.clock, 9*time.Second, frameStep(2, frameJPEG(t, 2))),
		after(f.clock, time.Second, frameStep(3, frameJPEG(t, 3))), // arrives at the deadline
	)
	require.Equal(t, map[string]any{"type": "error", "code": "timeout"}, conn.last(t))
	require.Len(t, worker.frames, 2)
	_, sr := f.getSession(id)
	require.Equal(t, StatusFailed, sr.Status)
	require.EqualValues(t, 10000, sr.DurationMs)
	require.Equal(t, analytics.OutcomeTimeout, f.rec.single(t).Outcome)
}

// A silent client hits the connection's read deadline instead.
func TestStreamTimeoutByReadDeadline(t *testing.T) {
	worker := &fakeWorker{}
	f := newFixture(t, worker, nil)
	id, token := f.createSession()

	deadline := &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}
	conn := f.stream(id, helloStep(token), frameStep(1, frameJPEG(t, 1)), errStep(deadline))
	require.Equal(t, map[string]any{"type": "error", "code": "timeout"}, conn.last(t))
	require.Equal(t, analytics.OutcomeTimeout, f.rec.single(t).Outcome)
}

func TestStreamClientDisconnects(t *testing.T) {
	worker := &fakeWorker{}
	f := newFixture(t, worker, nil)
	id, token := f.createSession()

	conn := f.stream(id, helloStep(token), frameStep(1, frameJPEG(t, 1)), errStep(io.ErrUnexpectedEOF))
	msgs := conn.texts(t)
	require.Len(t, msgs, 2, "ready and one state; nothing is sent to a client that left")
	require.Equal(t, "state", msgs[1]["type"])
	require.Equal(t, 0, conn.closeFrames())
	require.Equal(t, 1, worker.closed)

	_, sr := f.getSession(id)
	require.Equal(t, StatusFailed, sr.Status, "the session can never complete: one connection per session")
	require.Nil(t, sr.Passed)
	ev := f.rec.single(t)
	require.Equal(t, analytics.OutcomeAbandoned, ev.Outcome)
	require.Equal(t, 1, *ev.Frames)
}

func TestStreamInternalFailures(t *testing.T) {
	t.Run("worker cannot start", func(t *testing.T) {
		worker := &fakeWorker{spawnErr: errors.New("fork failed")}
		f := newFixture(t, worker, nil)
		id, token := f.createSession()
		conn := f.stream(id, helloStep(token))
		require.Equal(t, map[string]any{"type": "error", "code": "internal"}, conn.last(t))
		_, sr := f.getSession(id)
		require.Equal(t, StatusFailed, sr.Status)
	})
	t.Run("worker dies mid-stream", func(t *testing.T) {
		worker := &fakeWorker{frameErr: errWorkerExited}
		f := newFixture(t, worker, nil)
		id, token := f.createSession()
		conn := f.streamFrames(id, token, 1)
		require.Equal(t, map[string]any{"type": "error", "code": "internal"}, conn.last(t))
		require.Equal(t, analytics.OutcomeAbandoned, f.rec.single(t).Outcome)
	})
	t.Run("portrait refused by engine", func(t *testing.T) {
		worker := &fakeWorker{portraitErr: &RejectedError{Reason: "set_portrait: returned -1"}}
		f := newFixture(t, worker, nil)
		id, token := f.createSession()
		conn := f.stream(id, helloStep(token))
		require.Equal(t, "internal", conn.last(t)["code"], "the portrait was validated at creation; this is our problem")
	})
}

// State messages: one for the first frame, then at most every 500ms.
func TestStreamStateMessagesArePaced(t *testing.T) {
	worker := &fakeWorker{}
	f := newFixture(t, worker, nil)
	id, token := f.createSession()

	conn := f.streamFrames(id, token, 10) // frames at 0, 66ms, ..., 594ms
	var seqs []any
	for _, m := range conn.texts(t) {
		if m["type"] == "state" {
			seqs = append(seqs, m["seq"])
		}
	}
	require.Equal(t, []any{float64(1), float64(9)}, seqs, "frame 9 is the first at or past 500ms (8*66=528)")
}

func TestHandshakeUnauthorized(t *testing.T) {
	cases := map[string]func(f *fixture, id, token string) (string, step){
		"wrong token": func(f *fixture, id, token string) (string, step) { return id, helloStep("nope") },
		"unknown id":  func(f *fixture, id, token string) (string, step) { return "fs_unknown", helloStep(token) },
		"empty token": func(f *fixture, id, token string) (string, step) { return id, helloStep("") },
		"not a hello": func(f *fixture, id, token string) (string, step) {
			return id, textStep(map[string]string{"type": "frame"})
		},
		"binary first": func(f *fixture, id, token string) (string, step) { return id, binaryStep([]byte(token)) },
		"not json": func(f *fixture, id, token string) (string, step) {
			return id, func() (int, []byte, error) { return 1, []byte("{"), nil }
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			worker := &fakeWorker{}
			f := newFixture(t, worker, nil)
			id, token := f.createSession()
			streamID, hello := mk(f, id, token)
			conn := f.stream(streamID, hello, frameStep(1, frameJPEG(t, 1)))
			msgs := conn.texts(t)
			require.Len(t, msgs, 1)
			require.Equal(t, map[string]any{"type": "error", "code": "unauthorized"}, msgs[0])
			require.Equal(t, 1, conn.closeFrames())
			require.Equal(t, 0, worker.started, "no worker for a refused stream")

			_, sr := f.getSession(id)
			require.Equal(t, StatusPending, sr.Status, "a refused handshake does not consume the session")
			require.Empty(t, f.rec.events)
		})
	}
}

func TestHandshakeExpired(t *testing.T) {
	worker := &fakeWorker{}
	f := newFixture(t, worker, nil)
	id, token := f.createSession()
	f.clock.Advance(f.cfg.PendingTTL)

	conn := f.stream(id, helloStep(token))
	require.Equal(t, []map[string]any{{"type": "error", "code": "expired"}}, conn.texts(t))
	code, sr := f.getSession(id)
	require.Equal(t, 200, code)
	require.Equal(t, StatusExpired, sr.Status)
}

func TestHandshakeAlreadyStreaming(t *testing.T) {
	t.Run("after a finished stream", func(t *testing.T) {
		worker := &fakeWorker{verdicts: []Verdict{completed(0.2)}}
		f := newFixture(t, worker, nil)
		id, token := f.createSession()
		f.streamFrames(id, token, 1)

		conn := f.stream(id, helloStep(token))
		require.Equal(t, []map[string]any{{"type": "error", "code": "already_streaming"}}, conn.texts(t))
		require.Equal(t, 1, worker.started)
		_, sr := f.getSession(id)
		require.Equal(t, StatusCompleted, sr.Status, "the second connection changes nothing")
	})
	t.Run("while streaming", func(t *testing.T) {
		worker := &fakeWorker{}
		f := newFixture(t, worker, nil)
		id, token := f.createSession()
		require.NoError(t, f.store.Claim(t.Context(), id, f.clock.Now(), time.Hour))

		conn := f.stream(id, helloStep(token))
		require.Equal(t, []map[string]any{{"type": "error", "code": "already_streaming"}}, conn.texts(t))
	})
	t.Run("lost the claim race", func(t *testing.T) {
		// The store reports pending on Get but another replica claims first.
		worker := &fakeWorker{}
		f := newFixture(t, worker, nil)
		id, token := f.createSession()
		f.srv.streamer.store = racingStore{Store: f.store, id: id, clock: f.clock}

		conn := f.stream(id, helloStep(token))
		require.Equal(t, []map[string]any{{"type": "error", "code": "already_streaming"}}, conn.texts(t))
	})
}

// racingStore claims the session behind the handler's back between its Get
// and its Claim.
type racingStore struct {
	Store
	id    string
	clock *fakeClock
}

func (r racingStore) Claim(ctx context.Context, id string, startedAt time.Time, ttl time.Duration) error {
	_ = r.Store.Claim(ctx, r.id, r.clock.Now(), ttl)
	return r.Store.Claim(ctx, id, startedAt, ttl)
}

// Without the portrait there is nothing to verify against; the session is
// left pending so a retry that lands on the right replica can still run.
func TestHandshakePortraitMissingOnThisReplica(t *testing.T) {
	worker := &fakeWorker{}
	f := newFixture(t, worker, nil)
	id, token := f.createSession()
	f.srv.portraits.Delete(id)

	conn := f.stream(id, helloStep(token))
	require.Equal(t, []map[string]any{{"type": "error", "code": "internal"}}, conn.texts(t))
	_, sr := f.getSession(id)
	require.Equal(t, StatusPending, sr.Status)
}

func TestHandshakeClientLeavesBeforeHello(t *testing.T) {
	worker := &fakeWorker{}
	f := newFixture(t, worker, nil)
	id, _ := f.createSession()
	conn := f.stream(id)
	require.Empty(t, conn.texts(t))
	_, sr := f.getSession(id)
	require.Equal(t, StatusPending, sr.Status)
}

// The portrait leaves this process's memory when the stream starts and is
// gone whatever the ending.
func TestPortraitIsReleasedAfterStream(t *testing.T) {
	worker := &fakeWorker{verdicts: []Verdict{completed(0.1)}}
	f := newFixture(t, worker, nil)
	id, token := f.createSession()
	_, held := f.srv.portraits.Get(id)
	require.True(t, held)
	f.streamFrames(id, token, 1)
	_, held = f.srv.portraits.Get(id)
	require.False(t, held)
}
