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

func greyPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewGray(image.Rect(0, 0, 200, 200))
	for i := range img.Pix {
		img.Pix[i] = 128
	}
	var buf bytes.Buffer
	require.NoError(t, png.Encode(&buf, img))
	return buf.Bytes()
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

// portraitFromEnv reads IRIS_SMOKE_PORTRAIT as the worker would hand it to the
// engine, so a JPEG goes through the same workaround as in production.
func portraitFromEnv(tb testing.TB) ([]byte, bool) {
	path := os.Getenv("IRIS_SMOKE_PORTRAIT")
	if path == "" {
		return nil, false
	}
	return portraitForEngine(portraitFile(tb, path)), true
}

func TestEngineSmoke(t *testing.T) {
	eng, err := newEngine()
	require.NoError(t, err)
	require.NoError(t, eng.Clear())
	require.Equal(t, StateInitiated, eng.Verdict().State)

	// Bytes that are no image are refused by initiate, which the binding
	// reports as StateFailed rather than as an error.
	require.NoError(t, eng.SetPortrait([]byte("not an image")))
	require.Equal(t, StateFailed, eng.Verdict().State)

	// Frames after a terminal state are not processed.
	require.NoError(t, eng.Run(noisyFrame(t, 1), 0))
	require.Equal(t, StateFailed, eng.Verdict().State)

	// Clear starts over.
	require.NoError(t, eng.Clear())
	require.Equal(t, StateInitiated, eng.Verdict().State)

	// A decodable portrait without a face: the library has no failed state,
	// so it either refuses it in initiate or never completes. Log which, and
	// pin only that noise does not complete it.
	require.NoError(t, eng.SetPortrait(greyPNG(t)))
	t.Logf("initiate(grey PNG, no face): state=%v", eng.Verdict().State)
	for i := range 5 {
		require.NoError(t, eng.Run(noisyFrame(t, uint64(i)), 0))
	}
	require.NotEqual(t, StateCompleted, eng.Verdict().State, "a faceless portrait never completes")

	portrait, ok := portraitFromEnv(t)
	if !ok {
		t.Log("IRIS_SMOKE_PORTRAIT not set: skipping the INITIATED case")
		return
	}
	require.NoError(t, eng.Clear())
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
	payload := []byte(base64.StdEncoding.EncodeToString(portrait))
	if reply := handleWorkerMessage(eng, pipeMessage{Type: msgPortrait, Payload: payload}); reply.Type != msgState {
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

// TestEnginePortraitJPEG2000 answers the question the on-device arm hangs on:
// does this engine decode JPEG 2000? There the wallet can only hand the SDK
// the portrait it read off the chip, and DG2 is JPEG 2000 on most European
// documents, with no decoder available to fall back on in Dart or on either
// platform (irmamobile/docs/on-device-iris-face-verification-plan.md §9).
//
// initiate does not say why it refused a portrait, so the discriminator is
// two controls: a grey PNG (decoded, faceless) and bytes that are no image
// (undecodable). When the library treats them differently, a grey JPEG 2000
// that is treated like the PNG was decoded. When it treats them alike, the
// grey fixtures cannot tell, and only the conclusive form below can. Both
// packagings are tried, since a chip carries either: the JP2 container the
// fixture names and the bare codestream .j2k holds.
//
// Set IRIS_SMOKE_PORTRAIT_JP2 to a JPEG 2000 portrait *with a face* for the
// conclusive form of the same question.
func TestEnginePortraitJPEG2000(t *testing.T) {
	eng, err := newEngine()
	require.NoError(t, err)
	stateFor := func(portrait []byte) EngineState {
		require.NoError(t, eng.Clear())
		require.NoError(t, eng.SetPortrait(portrait))
		return eng.Verdict().State
	}

	pngState := stateFor(greyPNG(t))
	garbageState := stateFor([]byte("not an image"))
	t.Logf("initiate: grey PNG=%v, not an image=%v", pngState, garbageState)
	require.Equal(t, StateFailed, garbageState, "the undecodable control must be refused")

	for _, tc := range []struct{ name, path string }{
		{"jp2 container", "testdata/grey_200x200.jp2"},
		{"raw j2k codestream", "testdata/grey_200x200.j2k"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jp2State := stateFor(portraitFile(t, tc.path))
			t.Logf("initiate(grey %s, no face): state=%v", tc.name, jp2State)
			if pngState == garbageState {
				t.Skip("the library refuses faceless and undecodable portraits alike; set IRIS_SMOKE_PORTRAIT_JP2 for a conclusive answer")
			}
			require.Equal(t, pngState, jp2State,
				"a grey JPEG 2000 must be treated like a grey PNG; differing means the format was not decoded")
		})
	}

	path := os.Getenv("IRIS_SMOKE_PORTRAIT_JP2")
	if path == "" {
		t.Log("IRIS_SMOKE_PORTRAIT_JP2 not set: skipping the conclusive case (a JPEG 2000 portrait with a face)")
		return
	}
	require.Equal(t, StateInitiated, stateFor(portraitFile(t, path)),
		"a JPEG 2000 portrait with a face must keep the verifier going")
}

// TestEnginePortraitJPEG guards the JPEG workaround. libpassportreader-20261002
// refuses every JPEG portrait in initiate, and chip portraits are JPEG on
// driving licences and on some passports; portraitForEngine re-encodes them
// as PNG. The direct case only logs, so the test keeps passing when a vendor
// drop fixes JPEG; the log line says when the workaround can go. The worker
// case is the guard: a JPEG portrait with a face must keep the verifier going.
//
// Needs IRIS_SMOKE_PORTRAIT (a JPEG or PNG with a face); it is re-encoded as
// JPEG here, so a PNG works as well.
func TestEnginePortraitJPEG(t *testing.T) {
	src, ok := portraitFromEnv(t)
	if !ok {
		t.Skip("IRIS_SMOKE_PORTRAIT not set: needs a portrait with a face")
	}
	img, _, err := image.Decode(bytes.NewReader(src))
	if err != nil {
		t.Skipf("IRIS_SMOKE_PORTRAIT is not a JPEG or PNG Go can decode: %v", err)
	}
	var buf bytes.Buffer
	require.NoError(t, jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90}))
	portrait := buf.Bytes()

	eng, err := newEngine()
	require.NoError(t, err)
	require.NoError(t, eng.Clear())
	require.NoError(t, eng.SetPortrait(portrait))
	if eng.Verdict().State == StateInitiated {
		t.Log("the engine accepts a JPEG portrait directly: portraitForEngine is no longer needed")
	} else {
		t.Log("the engine refuses a JPEG portrait directly: portraitForEngine is still needed")
	}

	reply := handleWorkerMessage(eng, pipeMessage{Type: msgPortrait, Payload: []byte(base64.StdEncoding.EncodeToString(portrait))})
	require.Equal(t, msgState, reply.Type, "a JPEG portrait with a face must keep the verifier going: %s", reply.Payload)
	v, err := decodeVerdict(reply.Payload)
	require.NoError(t, err)
	require.Equal(t, StateInitiated, v.State)
}
