package main

import (
	"context"
	"errors"
	"image"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeEngine records what the worker loop asks of it and answers with a
// scripted verdict.
type fakeEngine struct {
	cleared      int
	portrait     string
	frames       []*image.YCbCr
	orientations []uint8
	verdict      Verdict
	// verdicts, when set, are returned one per Run; the last repeats.
	verdicts    []Verdict
	portraitErr error
	runErr      error
}

func (e *fakeEngine) Clear() error {
	e.cleared++
	e.verdict = initiated
	return nil
}

func (e *fakeEngine) SetPortrait(p string) error {
	e.portrait = p
	return e.portraitErr
}

func (e *fakeEngine) Run(img *image.YCbCr, orientation uint8) error {
	e.frames = append(e.frames, img)
	e.orientations = append(e.orientations, orientation)
	if e.runErr != nil {
		return e.runErr
	}
	if len(e.verdicts) > 0 {
		e.verdict = e.verdicts[min(len(e.frames)-1, len(e.verdicts)-1)]
	}
	return nil
}

func (e *fakeEngine) Verdict() Verdict { return e.verdict }

// pipeWorker runs the worker loop in-process over pipes and hands back the
// parent's ends. Closing toWorker ends the loop.
func pipeWorker(t *testing.T, eng Engine) (toWorker io.WriteCloser, fromWorker io.Reader, done <-chan error) {
	t.Helper()
	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	ch := make(chan error, 1)
	go func() {
		err := runWorkerLoop(reqR, respW, eng)
		_ = respW.Close()
		ch <- err
	}()
	t.Cleanup(func() { _ = reqW.Close() })
	return reqW, respR, ch
}

func TestWorkerLoopPortraitThenFrames(t *testing.T) {
	eng := &fakeEngine{verdicts: []Verdict{initiated, completed(0.3)}}
	in, out, done := pipeWorker(t, eng)

	require.NoError(t, writeMessage(in, pipeMessage{Type: msgPortrait, Payload: []byte("UE9SVFJBSVQ=")}))
	reply, err := readMessage(out)
	require.NoError(t, err)
	require.Equal(t, msgState, reply.Type)
	require.Equal(t, 1, eng.cleared, "clear() precedes set_portrait()")
	require.Equal(t, "UE9SVFJBSVQ=", eng.portrait)

	jpeg := frameJPEG(t, 1)
	require.NoError(t, writeMessage(in, frameMessage(1, jpeg)))
	reply, err = readMessage(out)
	require.NoError(t, err)
	require.Equal(t, msgState, reply.Type)
	require.Len(t, eng.frames, 1)
	require.Equal(t, image.YCbCrSubsampleRatio420, eng.frames[0].SubsampleRatio)
	require.Equal(t, []uint8{1}, eng.orientations)

	require.NoError(t, writeMessage(in, frameMessage(0, jpeg)))
	reply, err = readMessage(out)
	require.NoError(t, err)
	require.Equal(t, msgResult, reply.Type)
	v, err := decodeVerdict(reply.Payload)
	require.NoError(t, err)
	require.Equal(t, StateCompleted, v.State)
	require.InDelta(t, 0.3, v.Distance, 1e-6)

	require.NoError(t, in.Close())
	require.NoError(t, <-done, "a closed pipe is a clean exit")
}

// Bad input is answered, not fatal: the worker keeps serving.
func TestWorkerLoopRejectsBadInputAndContinues(t *testing.T) {
	eng := &fakeEngine{}
	in, out, _ := pipeWorker(t, eng)

	require.NoError(t, writeMessage(in, frameMessage(0, []byte("not a jpeg"))))
	reply, err := readMessage(out)
	require.NoError(t, err)
	require.Equal(t, msgReject, reply.Type)
	require.Contains(t, string(reply.Payload), "decode jpeg")
	require.Empty(t, eng.frames, "nothing reaches the engine")

	require.NoError(t, writeMessage(in, pipeMessage{Type: 99}))
	reply, err = readMessage(out)
	require.NoError(t, err)
	require.Equal(t, msgReject, reply.Type)

	eng.runErr = errors.New("engine says no")
	require.NoError(t, writeMessage(in, frameMessage(0, frameJPEG(t, 1))))
	reply, err = readMessage(out)
	require.NoError(t, err)
	require.Equal(t, msgReject, reply.Type)
	require.Contains(t, string(reply.Payload), "engine says no")

	eng.runErr = nil
	require.NoError(t, writeMessage(in, frameMessage(0, frameJPEG(t, 2))))
	reply, err = readMessage(out)
	require.NoError(t, err)
	require.Equal(t, msgState, reply.Type, "still serving after rejections")
}

func TestWorkerLoopPortraitRejected(t *testing.T) {
	eng := &fakeEngine{portraitErr: errors.New("set_portrait returned -1")}
	in, out, _ := pipeWorker(t, eng)
	require.NoError(t, writeMessage(in, pipeMessage{Type: msgPortrait, Payload: []byte("%%%")}))
	reply, err := readMessage(out)
	require.NoError(t, err)
	require.Equal(t, msgReject, reply.Type)
}

// --- the real subprocess plumbing, with this test binary as the child ------

// TestMain lets the test binary double as a worker: with IRIS_TEST_WORKER=1 it
// speaks the pipe protocol on stdin/stdout with a fake engine, with
// IRIS_TEST_WORKER=exit it dies at once. That exercises spawn, call, kill
// and reaping for real, without the C library.
func TestMain(m *testing.M) {
	switch os.Getenv("IRIS_TEST_WORKER") {
	case "1":
		eng := &fakeEngine{verdicts: []Verdict{initiated, completed(0.3)}}
		if err := runWorkerLoop(os.Stdin, os.Stdout, eng); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	case "exit":
		os.Exit(3)
	}
	os.Exit(m.Run())
}

func testBinaryFactory(t *testing.T, behaviour string) WorkerFactory {
	t.Helper()
	exe, err := os.Executable()
	require.NoError(t, err)
	// The child inherits this process's environment.
	t.Setenv("IRIS_TEST_WORKER", behaviour)
	return newSubprocessFactory(exe, []string{"-test.run=^$"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestSubprocessWorkerRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	w, err := testBinaryFactory(t, "1")(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	v, err := w.SetPortrait(ctx, "UE9SVFJBSVQ=")
	require.NoError(t, err)
	require.Equal(t, StateInitiated, v.State)

	v, err = w.Frame(ctx, 0, frameJPEG(t, 1))
	require.NoError(t, err)
	require.Equal(t, StateInitiated, v.State)

	_, err = w.Frame(ctx, 0, []byte("garbage"))
	var rejected *RejectedError
	require.ErrorAs(t, err, &rejected)

	v, err = w.Frame(ctx, 2, frameJPEG(t, 2))
	require.NoError(t, err)
	require.Equal(t, StateCompleted, v.State)
	require.InDelta(t, 0.3, v.Distance, 1e-6)

	require.NoError(t, w.Close())
	require.NoError(t, w.Close(), "Close is idempotent")
	_, err = w.SetPortrait(ctx, "x")
	require.Error(t, err, "a closed worker cannot be used")
}

func TestSubprocessWorkerDies(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	w, err := testBinaryFactory(t, "exit")(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	_, err = w.SetPortrait(ctx, "UE9SVFJBSVQ=")
	require.Error(t, err)
	require.NotErrorIs(t, err, &RejectedError{}, "a dead worker is not a rejection")
}

// Concurrent calls on one worker are serialised, never interleaved on the pipe.
func TestSubprocessWorkerSerialisesCalls(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	w, err := testBinaryFactory(t, "1")(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Close() }()

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := w.SetPortrait(ctx, "UE9SVFJBSVQ=")
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}
