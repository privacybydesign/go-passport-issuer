package main

import (
	"errors"
	"fmt"
	"image"
	"time"
)

// EngineState mirrors passportreader_face_verifier_state_t.
type EngineState uint8

const (
	StateInitiated EngineState = 0
	StateFailed    EngineState = 1
	StateCompleted EngineState = 2
)

// Terminal reports whether the engine has reached a verdict; frames fed after
// that are no-ops in the library.
func (s EngineState) Terminal() bool { return s == StateFailed || s == StateCompleted }

func (s EngineState) String() string {
	switch s {
	case StateInitiated:
		return "initiated"
	case StateFailed:
		return "failed"
	case StateCompleted:
		return "completed"
	}
	return fmt.Sprintf("state(%d)", uint8(s))
}

// Verdict is the engine's state after a call, with the distance between the
// portrait and the live face. Distance is meaningful only when State is
// StateCompleted; lower is better.
type Verdict struct {
	State    EngineState
	Distance float64
	// DecodeTime and RunTime are the worker's time for the frame behind this
	// verdict: the JPEG decode and the library's run call. The worker sets
	// them on frame replies only; the engine does not time itself.
	DecodeTime, RunTime time.Duration
}

// Engine is the face verifier as the worker process sees it. The C library
// keeps one verifier as process-global state, so exactly one Engine value is
// used per worker process, and one worker process serves one session.
type Engine interface {
	// Clear resets the verifier; it must precede SetPortrait.
	Clear() error
	// SetPortrait loads the reference portrait (base64 JPEG or PNG). A
	// portrait without a detectable face moves the state to StateFailed at
	// once.
	SetPortrait(base64Portrait string) error
	// Run feeds one full-range 4:2:0 frame.
	Run(img *image.YCbCr, orientation uint8) error
	// Verdict reads the current state and distance.
	Verdict() Verdict
}

// ErrEngineUnavailable is returned by newEngine on every platform but
// linux/amd64 with cgo, the only one the vendor library exists for.
var ErrEngineUnavailable = errors.New("iris engine unavailable on this platform (needs linux/amd64, cgo, clang and lld)")
