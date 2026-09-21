package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"time"
)

// --- worker side -----------------------------------------------------------

// runWorkerLoop serves one Engine over the pipes until the parent closes its
// end. Engine and decode failures are replies (msgReject), not loop errors:
// the worker stays up for the next message.
func runWorkerLoop(r io.Reader, w io.Writer, eng Engine) error {
	for {
		m, err := readMessage(r)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read request: %w", err)
		}
		if err := writeMessage(w, handleWorkerMessage(eng, m)); err != nil {
			return fmt.Errorf("write reply: %w", err)
		}
	}
}

func handleWorkerMessage(eng Engine, m pipeMessage) pipeMessage {
	switch m.Type {
	case msgPortrait:
		if err := eng.Clear(); err != nil {
			return rejectMessage("clear: " + err.Error())
		}
		if err := eng.SetPortrait(string(m.Payload)); err != nil {
			return rejectMessage("set_portrait: " + err.Error())
		}
		return verdictMessage(eng.Verdict())
	case msgFrame:
		orientation, jpegBytes, err := decodeFramePayload(m.Payload)
		if err != nil {
			return rejectMessage(err.Error())
		}
		img, err := decodeFrameJPEG(jpegBytes)
		if err != nil {
			return rejectMessage(err.Error())
		}
		if err := eng.Run(img, orientation); err != nil {
			return rejectMessage("run: " + err.Error())
		}
		return verdictMessage(eng.Verdict())
	default:
		return rejectMessage(fmt.Sprintf("unknown message type %d", m.Type))
	}
}

// runSelftest is `--worker --selftest`: it links the library and initialises
// a verifier, which is what readyz needs to know a node can run sessions.
func runSelftest() error {
	eng, err := newEngine()
	if err != nil {
		return err
	}
	return eng.Clear()
}

// --- parent side -----------------------------------------------------------

// Worker is the parent's handle on one session's engine. Calls are
// synchronous and serialised. Any error other than *RejectedError means the
// worker is unusable and must be closed.
type Worker interface {
	SetPortrait(ctx context.Context, base64Portrait string) (Verdict, error)
	Frame(ctx context.Context, orientation uint8, jpeg []byte) (Verdict, error)
	// Close stops the worker, and with it the portrait and frames it held.
	Close() error
}

// WorkerFactory starts a fresh worker for one session.
type WorkerFactory func(ctx context.Context) (Worker, error)

// RejectedError is a msgReject reply: the worker refused this input but is
// alive. The stream reports it as bad_frame.
type RejectedError struct{ Reason string }

func (e *RejectedError) Error() string { return "worker rejected input: " + e.Reason }

var errWorkerExited = errors.New("worker exited")

// workerCallTimeout bounds one round trip. A frame takes tens of
// milliseconds; a worker silent for this long is stuck.
const workerCallTimeout = 10 * time.Second

// newSubprocessFactory returns a factory that runs exe with args as the worker
// process. The server passes its own executable and --worker; a test can
// pass anything that speaks the protocol on stdin/stdout. The child's stderr
// is the parent's, so its log lines land in the same stream.
func newSubprocessFactory(exe string, args []string, log *slog.Logger) WorkerFactory {
	return func(context.Context) (Worker, error) {
		return startSubprocessWorker(exe, args, log)
	}
}

// selfExecutable is what the server re-executes for its workers.
func selfExecutable() string {
	exe, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}
	return exe
}

type subprocessWorker struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	replies <-chan replyOrErr
	done    chan struct{}
	once    sync.Once
	mu      sync.Mutex
	log     *slog.Logger
}

type replyOrErr struct {
	msg pipeMessage
	err error
}

func startSubprocessWorker(exe string, args []string, log *slog.Logger) (*subprocessWorker, error) {
	cmd := exec.Command(exe, args...)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("worker stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("worker stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start worker: %w", err)
	}
	replies := make(chan replyOrErr)
	w := &subprocessWorker{cmd: cmd, stdin: stdin, replies: replies, done: make(chan struct{}), log: log}
	go func() {
		defer close(replies)
		for {
			m, err := readMessage(stdout)
			select {
			case replies <- replyOrErr{msg: m, err: err}:
			case <-w.done:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	log.Debug("worker started", "pid", cmd.Process.Pid)
	return w, nil
}

func (w *subprocessWorker) SetPortrait(ctx context.Context, base64Portrait string) (Verdict, error) {
	return w.call(ctx, pipeMessage{Type: msgPortrait, Payload: []byte(base64Portrait)})
}

func (w *subprocessWorker) Frame(ctx context.Context, orientation uint8, jpeg []byte) (Verdict, error) {
	return w.call(ctx, frameMessage(orientation, jpeg))
}

func (w *subprocessWorker) call(ctx context.Context, m pipeMessage) (Verdict, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := writeMessage(w.stdin, m); err != nil {
		return Verdict{}, fmt.Errorf("write to worker: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, workerCallTimeout)
	defer cancel()
	select {
	case r, ok := <-w.replies:
		if !ok {
			return Verdict{}, errWorkerExited
		}
		if r.err != nil {
			return Verdict{}, fmt.Errorf("read from worker: %w", r.err)
		}
		return parseReply(r.msg)
	case <-ctx.Done():
		return Verdict{}, fmt.Errorf("worker call: %w", ctx.Err())
	}
}

func parseReply(m pipeMessage) (Verdict, error) {
	switch m.Type {
	case msgState, msgResult:
		return decodeVerdict(m.Payload)
	case msgReject:
		return Verdict{}, &RejectedError{Reason: string(m.Payload)}
	default:
		return Verdict{}, fmt.Errorf("unexpected reply type %d from worker", m.Type)
	}
}

// Close kills the worker; it never waits for a graceful exit because the
// worker holds nothing worth flushing.
func (w *subprocessWorker) Close() error {
	w.once.Do(func() {
		close(w.done)
		_ = w.stdin.Close()
		_ = w.cmd.Process.Kill()
		// Wait reaps the child and closes the stdout pipe, which ends the
		// reader goroutine.
		_ = w.cmd.Wait()
		w.log.Debug("worker stopped", "pid", w.cmd.Process.Pid)
	})
	return nil
}

// checkWorkerSpawn runs `--worker --selftest`, for readyz on builds that
// carry the engine: it proves this node can start a worker and initialise
// the library, in a few tens of milliseconds.
func checkWorkerSpawn(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, selfExecutable(), "--worker", "--selftest").CombinedOutput()
	if err != nil {
		return fmt.Errorf("worker selftest: %w: %s", err, out)
	}
	return nil
}
