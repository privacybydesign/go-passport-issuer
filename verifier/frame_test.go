package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseFrameLittleEndianLayout(t *testing.T) {
	b := []byte{
		0x01, 0x02, 0x03, 0x04, // seq = 0x04030201
		0x10, 0x27, 0x00, 0x00, // ts_ms = 10000
		0x80, 0x02, // width = 640
		0xe0, 0x01, // height = 480
		0x03,             // orientation = 270
		0x00, 0x00, 0x00, // reserved
		0xff, 0xd8, // JPEG bytes
	}
	h, jpeg, err := parseFrame(b)
	require.NoError(t, err)
	require.Equal(t, FrameHeader{Seq: 0x04030201, TsMs: 10000, Width: 640, Height: 480, Orientation: 3}, h)
	require.Equal(t, []byte{0xff, 0xd8}, jpeg)
}

func TestFrameHeaderEncodeRoundTrip(t *testing.T) {
	want := FrameHeader{Seq: 42, TsMs: 2772, Width: 320, Height: 240, Orientation: 1}
	h, jpeg, err := parseFrame(want.encode([]byte("jpeg")))
	require.NoError(t, err)
	require.Equal(t, want, h)
	require.Equal(t, []byte("jpeg"), jpeg)
}

func TestParseFrameErrors(t *testing.T) {
	_, _, err := parseFrame(make([]byte, frameHeaderSize-1))
	require.ErrorIs(t, err, errShortFrame)

	_, _, err = parseFrame(make([]byte, frameHeaderSize))
	require.ErrorIs(t, err, errEmptyFrame)

	bad := FrameHeader{Orientation: 4}.encode([]byte("jpeg"))
	_, _, err = parseFrame(bad)
	require.Error(t, err)
}
