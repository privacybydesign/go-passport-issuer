//go:build linux && amd64 && cgo

package main

// Smoke test and benchmark against the real libpassportreader. They run only
// where the library links (linux/amd64, clang + lld), i.e. in CI and in the
// build container. Set IRIS_SMOKE_PORTRAIT to a JPEG or PNG with a face for
// the INITIATED case and the benchmark; without one the engine fails the
// portrait at once and nothing can be measured.

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/jpeg"
	"image/png"
	"math/rand/v2"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func greyPNGBase64(t *testing.T) string {
	t.Helper()
	img := image.NewGray(image.Rect(0, 0, 200, 200))
	for i := range img.Pix {
		img.Pix[i] = 128
	}
	var buf bytes.Buffer
	require.NoError(t, png.Encode(&buf, img))
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// noisyFrame is a 640x480 frame of grey noise: no face, but real work for
// the detector, and different bytes per frame.
func noisyFrame(tb testing.TB, seed uint64) *image.YCbCr {
	tb.Helper()
	r := rand.New(rand.NewPCG(seed, 1))
	img := image.NewRGBA(image.Rect(0, 0, 640, 480))
	for i := range img.Pix {
		img.Pix[i] = uint8(100 + r.IntN(56))
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 80}); err != nil {
		tb.Fatal(err)
	}
	frame, err := decodeFrameJPEG(buf.Bytes())
	if err != nil {
		tb.Fatal(err)
	}
	return frame
}

func portraitFromEnv(tb testing.TB) (string, bool) {
	path := os.Getenv("IRIS_SMOKE_PORTRAIT")
	if path == "" {
		return "", false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		tb.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b), true
}

func TestEngineSmoke(t *testing.T) {
	eng, err := newEngine()
	require.NoError(t, err)
	require.NoError(t, eng.Clear())
	require.Equal(t, StateInitiated, eng.Verdict().State)

	// Malformed base64 is refused (documented as returning -1).
	require.Error(t, eng.SetPortrait("%%% not base64 %%%"))

	// A portrait without a detectable face fails at once. The return value
	// of set_portrait in this case is not documented; log it, pin the state.
	require.NoError(t, eng.Clear())
	err = eng.SetPortrait(greyPNGBase64(t))
	t.Logf("set_portrait(no face): err=%v", err)
	require.Equal(t, StateFailed, eng.Verdict().State)

	// Frames after a terminal state are no-ops.
	require.NoError(t, eng.Run(noisyFrame(t, 1), 0))
	require.Equal(t, StateFailed, eng.Verdict().State)

	// clear() starts over.
	require.NoError(t, eng.Clear())
	require.Equal(t, StateInitiated, eng.Verdict().State)

	portrait, ok := portraitFromEnv(t)
	if !ok {
		t.Log("IRIS_SMOKE_PORTRAIT not set: skipping the INITIATED case")
		return
	}
	require.NoError(t, eng.SetPortrait(portrait))
	require.Equal(t, StateInitiated, eng.Verdict().State, "a portrait with a face keeps the verifier going")
	for i := range 15 {
		require.NoError(t, eng.Run(noisyFrame(t, uint64(i)), 0))
	}
	require.Equal(t, StateInitiated, eng.Verdict().State, "frames without a face do not decide")
	require.Equal(t, image.YCbCrSubsampleRatio420, noisyFrame(t, 0).SubsampleRatio)
}

// readyz relies on this succeeding in a fresh process.
func TestEngineSelftest(t *testing.T) {
	require.NoError(t, runSelftest())
}

func BenchmarkEngineFrame(b *testing.B) {
	portrait, ok := portraitFromEnv(b)
	if !ok {
		b.Skip("set IRIS_SMOKE_PORTRAIT to a portrait with a face")
	}
	eng, err := newEngine()
	if err != nil {
		b.Fatal(err)
	}
	if err := eng.Clear(); err != nil {
		b.Fatal(err)
	}
	if err := eng.SetPortrait(portrait); err != nil {
		b.Fatal(err)
	}
	frames := make([]*image.YCbCr, 15)
	for i := range frames {
		frames[i] = noisyFrame(b, uint64(i))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := eng.Run(frames[i%len(frames)], 0); err != nil {
			b.Fatal(err)
		}
		if eng.Verdict().State.Terminal() {
			b.Fatalf("engine decided on noise: %v", eng.Verdict())
		}
	}
}

// The whole worker path for one frame, JPEG decode included, as the parent
// sees it: this is the per-frame CPU figure the capacity plan needs.
func BenchmarkWorkerFrame(b *testing.B) {
	portrait, ok := portraitFromEnv(b)
	if !ok {
		b.Skip("set IRIS_SMOKE_PORTRAIT to a portrait with a face")
	}
	eng, err := newEngine()
	if err != nil {
		b.Fatal(err)
	}
	if reply := handleWorkerMessage(eng, pipeMessage{Type: msgPortrait, Payload: []byte(portrait)}); reply.Type != msgState {
		b.Fatalf("portrait not accepted: %s", reply.Payload)
	}
	img := image.NewRGBA(image.Rect(0, 0, 640, 480))
	for i := range img.Pix {
		img.Pix[i] = uint8(90 + i%70)
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 80}); err != nil {
		b.Fatal(err)
	}
	frame := frameMessage(0, buf.Bytes())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if reply := handleWorkerMessage(eng, frame); reply.Type != msgState {
			b.Fatalf("unexpected reply %d: %s", reply.Type, reply.Payload)
		}
	}
}
