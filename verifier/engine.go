package main

import (
	"errors"
	"fmt"
	"image"
	"time"
)

// EngineState is the verifier's view of a session's engine. The library itself
// has only INITIATED and COMPLETED; StateFailed is what the binding reports
// when the library refuses the portrait, which ends the session at once.
type EngineState uint8

const (
	StateInitiated EngineState = 0
	StateFailed    EngineState = 1
	StateCompleted EngineState = 2
)

// Terminal reports whether the engine has reached a verdict; frames fed after
// that are not processed.
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

// Verdict is the engine's state after a call, with the match score between
// the portrait and the live face. Score is in [0, 1] and meaningful only when
// State is StateCompleted; higher is a stronger match.
type Verdict struct {
	State EngineState
	Score float64
	// DecodeTime and RunTime are the worker's time for the frame behind this
	// verdict: the JPEG decode and the library's run call. The worker sets
	// them on frame replies only; the engine does not time itself.
	DecodeTime, RunTime time.Duration
}

// Engine is the face verifier as the worker process sees it. One worker
// process serves one session, so a crash or a leak in the vendor library
// takes down that session only.
type Engine interface {
	// Clear starts a fresh verification; it must precede SetPortrait.
	Clear() error
	// SetPortrait loads the reference portrait (JPEG, PNG or JPEG 2000
	// bytes). A portrait the library refuses, such as one without a
	// detectable face, moves the state to StateFailed at once.
	SetPortrait(portrait []byte) error
	// Run feeds one full-range 4:2:0 frame.
	Run(img *image.YCbCr, orientation uint8) error
	// Verdict reads the current state and score.
	Verdict() Verdict
}

// ErrEngineUnavailable is returned by newEngine on every platform but
// linux/amd64 with cgo, the only one the vendor library exists for.
var ErrEngineUnavailable = errors.New("iris engine unavailable on this platform (needs linux/amd64, cgo, clang and lld)")
