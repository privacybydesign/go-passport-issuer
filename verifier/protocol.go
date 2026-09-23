package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
)

// The parent and its worker talk over the worker's stdin and stdout with
// length-prefixed messages: a 4-byte big-endian length that covers the type
// byte and the payload, then the type byte, then the payload. Every request
// from the parent gets exactly one reply, so the parent calls synchronously.

type msgType uint8

const (
	// msgPortrait, parent → worker: the base64 portrait. The worker runs
	// clear() and set_portrait() and replies with the verdict.
	msgPortrait msgType = 1
	// msgFrame, parent → worker: one byte orientation, then JPEG bytes.
	msgFrame msgType = 2
	// msgState, worker → parent: a verdict while the engine is INITIATED.
	msgState msgType = 3
	// msgResult, worker → parent: a verdict in a terminal state.
	msgResult msgType = 4
	// msgReject, worker → parent: a UTF-8 reason. The input was refused (bad
	// JPEG, engine error) but the worker is alive and can take the next one.
	msgReject msgType = 5
)

// maxPipeMessage bounds one message. Frames are already capped by
// max_frame_bytes, so this only turns a corrupt length prefix into an error
// instead of a huge allocation.
const maxPipeMessage = 16 << 20

type pipeMessage struct {
	Type    msgType
	Payload []byte
}

func writeMessage(w io.Writer, m pipeMessage) error {
	n := 1 + len(m.Payload)
	if n > maxPipeMessage {
		return fmt.Errorf("pipe message of %d bytes exceeds %d", n, maxPipeMessage)
	}
	buf := make([]byte, 4+n)
	binary.BigEndian.PutUint32(buf, uint32(n))
	buf[4] = byte(m.Type)
	copy(buf[5:], m.Payload)
	_, err := w.Write(buf)
	return err
}

// readMessage returns io.EOF unwrapped when the stream ends cleanly between
// messages, so the worker can tell a closed pipe from a truncated message.
func readMessage(r io.Reader) (pipeMessage, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return pipeMessage{}, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || n > maxPipeMessage {
		return pipeMessage{}, fmt.Errorf("bad pipe message length %d", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return pipeMessage{}, fmt.Errorf("read pipe message body: %w", err)
	}
	return pipeMessage{Type: msgType(body[0]), Payload: body[1:]}, nil
}

// verdictPayloadSize: state, distance, decode and run time.
const verdictPayloadSize = 13

// verdictMessage encodes a Verdict as msgState or msgResult, depending on
// whether the state is terminal: one byte state, the distance as an IEEE-754
// float32 (the library's own precision), then the decode and run times in
// microseconds as uint32; all little-endian.
func verdictMessage(v Verdict) pipeMessage {
	buf := make([]byte, verdictPayloadSize)
	buf[0] = byte(v.State)
	binary.LittleEndian.PutUint32(buf[1:], math.Float32bits(float32(v.Distance)))
	binary.LittleEndian.PutUint32(buf[5:], micros(v.DecodeTime))
	binary.LittleEndian.PutUint32(buf[9:], micros(v.RunTime))
	t := msgState
	if v.State.Terminal() {
		t = msgResult
	}
	return pipeMessage{Type: t, Payload: buf}
}

func decodeVerdict(p []byte) (Verdict, error) {
	if len(p) != verdictPayloadSize {
		return Verdict{}, fmt.Errorf("verdict payload is %d bytes, want %d", len(p), verdictPayloadSize)
	}
	state := EngineState(p[0])
	if state > StateCompleted {
		return Verdict{}, fmt.Errorf("unknown engine state %d", p[0])
	}
	return Verdict{
		State:      state,
		Distance:   float64(math.Float32frombits(binary.LittleEndian.Uint32(p[1:]))),
		DecodeTime: time.Duration(binary.LittleEndian.Uint32(p[5:])) * time.Microsecond,
		RunTime:    time.Duration(binary.LittleEndian.Uint32(p[9:])) * time.Microsecond,
	}, nil
}

// micros clamps d to what a uint32 of microseconds holds (over an hour).
func micros(d time.Duration) uint32 {
	us := d.Microseconds()
	switch {
	case us < 0:
		return 0
	case us > math.MaxUint32:
		return math.MaxUint32
	}
	return uint32(us)
}

func rejectMessage(reason string) pipeMessage {
	return pipeMessage{Type: msgReject, Payload: []byte(reason)}
}

func frameMessage(orientation uint8, jpeg []byte) pipeMessage {
	p := make([]byte, 1+len(jpeg))
	p[0] = orientation
	copy(p[1:], jpeg)
	return pipeMessage{Type: msgFrame, Payload: p}
}

func decodeFramePayload(p []byte) (orientation uint8, jpeg []byte, err error) {
	if len(p) < 2 {
		return 0, nil, errors.New("frame payload has no JPEG bytes")
	}
	return p[0], p[1:], nil
}
