package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// frameHeaderSize is the fixed prefix of every binary WebSocket frame: seq
// uint32, ts_ms uint32, width uint16, height uint16, orientation uint8,
// three reserved bytes; all little-endian.
const frameHeaderSize = 16

// FrameHeader precedes the JPEG bytes in every binary frame.
type FrameHeader struct {
	Seq  uint32 // the client's frame counter, echoed in state messages
	TsMs uint32 // milliseconds since the client's first frame
	// Width and Height are what the client reports. The JPEG's own
	// dimensions are authoritative for the limits and for the engine.
	Width, Height uint16
	Orientation   uint8 // passportreader_image_orientation_t, 0–3
}

var (
	errShortFrame = errors.New("frame shorter than its 16-byte header")
	errEmptyFrame = errors.New("frame has no JPEG payload")
)

// parseFrame splits a binary message into its header and JPEG bytes. The
// returned slice aliases b.
func parseFrame(b []byte) (FrameHeader, []byte, error) {
	if len(b) < frameHeaderSize {
		return FrameHeader{}, nil, errShortFrame
	}
	h := FrameHeader{
		Seq:         binary.LittleEndian.Uint32(b[0:4]),
		TsMs:        binary.LittleEndian.Uint32(b[4:8]),
		Width:       binary.LittleEndian.Uint16(b[8:10]),
		Height:      binary.LittleEndian.Uint16(b[10:12]),
		Orientation: b[12],
	}
	if h.Orientation > 3 {
		return FrameHeader{}, nil, fmt.Errorf("orientation %d out of range 0-3", h.Orientation)
	}
	if len(b) == frameHeaderSize {
		return FrameHeader{}, nil, errEmptyFrame
	}
	return h, b[frameHeaderSize:], nil
}

// encode is the client side of parseFrame; it documents the layout and
// serves the tests.
func (h FrameHeader) encode(jpeg []byte) []byte {
	b := make([]byte, frameHeaderSize+len(jpeg))
	binary.LittleEndian.PutUint32(b[0:4], h.Seq)
	binary.LittleEndian.PutUint32(b[4:8], h.TsMs)
	binary.LittleEndian.PutUint16(b[8:10], h.Width)
	binary.LittleEndian.PutUint16(b[10:12], h.Height)
	b[12] = h.Orientation
	copy(b[frameHeaderSize:], jpeg)
	return b
}
