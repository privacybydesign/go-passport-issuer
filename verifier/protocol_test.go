package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPipeMessageRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := []pipeMessage{
		{Type: msgPortrait, Payload: []byte("cG9ydHJhaXQ=")},
		frameMessage(2, []byte{0xff, 0xd8, 0xff}),
		rejectMessage("bad jpeg"),
		verdictMessage(initiated),
		verdictMessage(completed(0.41)),
	}
	for _, m := range in {
		require.NoError(t, writeMessage(&buf, m))
	}
	for _, want := range in {
		got, err := readMessage(&buf)
		require.NoError(t, err)
		require.Equal(t, want.Type, got.Type)
		require.Equal(t, want.Payload, got.Payload)
	}
	_, err := readMessage(&buf)
	require.ErrorIs(t, err, io.EOF, "a clean end of stream is io.EOF, unwrapped")
}

// The length prefix covers the type byte and the payload, big-endian.
func TestPipeMessageLayout(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, writeMessage(&buf, pipeMessage{Type: msgFrame, Payload: []byte{1, 2, 3}}))
	require.Equal(t, []byte{0, 0, 0, 4, byte(msgFrame), 1, 2, 3}, buf.Bytes())
}

func TestReadMessageTruncatedIsNotEOF(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, writeMessage(&buf, pipeMessage{Type: msgFrame, Payload: []byte("payload")}))
	truncated := buf.Bytes()[:buf.Len()-3]
	_, err := readMessage(bytes.NewReader(truncated))
	require.Error(t, err)
	require.NotErrorIs(t, err, io.EOF)
}

func TestReadMessageRejectsBadLength(t *testing.T) {
	var zero [4]byte
	_, err := readMessage(bytes.NewReader(zero[:]))
	require.Error(t, err)

	var huge [4]byte
	binary.BigEndian.PutUint32(huge[:], maxPipeMessage+1)
	_, err = readMessage(bytes.NewReader(huge[:]))
	require.Error(t, err)
}

func TestWriteMessageRejectsOversize(t *testing.T) {
	err := writeMessage(io.Discard, pipeMessage{Type: msgFrame, Payload: make([]byte, maxPipeMessage)})
	require.Error(t, err)
}

func TestVerdictMessageTypeFollowsState(t *testing.T) {
	require.Equal(t, msgState, verdictMessage(initiated).Type)
	require.Equal(t, msgResult, verdictMessage(Verdict{State: StateFailed}).Type)
	require.Equal(t, msgResult, verdictMessage(completed(0.5)).Type)
}

func TestVerdictRoundTrip(t *testing.T) {
	for _, v := range []Verdict{initiated, {State: StateFailed}, completed(0.41), completed(1.25)} {
		got, err := decodeVerdict(verdictMessage(v).Payload)
		require.NoError(t, err)
		require.Equal(t, v.State, got.State)
		// The wire carries the library's float32.
		require.InDelta(t, v.Distance, got.Distance, 1e-6)
	}
}

func TestDecodeVerdictRejectsGarbage(t *testing.T) {
	_, err := decodeVerdict([]byte{0, 0})
	require.Error(t, err)
	_, err = decodeVerdict([]byte{9, 0, 0, 0, 0})
	require.Error(t, err, "unknown state")
}

func TestFramePayload(t *testing.T) {
	m := frameMessage(3, []byte("jpeg"))
	orientation, jpeg, err := decodeFramePayload(m.Payload)
	require.NoError(t, err)
	require.Equal(t, uint8(3), orientation)
	require.Equal(t, []byte("jpeg"), jpeg)

	_, _, err = decodeFramePayload([]byte{1})
	require.Error(t, err, "orientation without a JPEG")
}
