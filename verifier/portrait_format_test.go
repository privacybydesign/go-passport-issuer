package main

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPortraitFormat(t *testing.T) {
	jp2, j2k := portraitFile(t, "testdata/grey_200x200.jp2"), portraitFile(t, "testdata/grey_200x200.j2k")
	for _, tc := range []struct {
		name string
		b    []byte
		want string
	}{
		{"jpeg", testJPEG(t, 8, 8, color.RGBA{A: 255}), "jpeg"},
		{"png", testPNG(t), "png"},
		{"jp2", jp2, "jp2"},
		{"j2k", j2k, "j2k"},
		{"other", []byte("not an image"), "unknown"},
		{"empty", nil, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, portraitFormat(tc.b))
			require.Equal(t, tc.want, portraitFormatOfBase64(base64.StdEncoding.EncodeToString(tc.b)))
		})
	}
	require.Equal(t, "unknown", portraitFormatOfBase64("%%% not base64 %%%"))
}

func TestPortraitForEngineTranscodesJPEG(t *testing.T) {
	src := testJPEG(t, 40, 30, color.RGBA{R: 200, G: 120, B: 60, A: 255})
	out := portraitForEngine(src)
	require.Equal(t, "png", portraitFormat(out))
	img, err := png.Decode(bytes.NewReader(out))
	require.NoError(t, err)
	require.Equal(t, image.Rect(0, 0, 40, 30), img.Bounds())
}

func TestPortraitForEnginePassesOthersThrough(t *testing.T) {
	p := testPNG(t)
	require.Equal(t, p, portraitForEngine(p))
	jp2 := portraitFile(t, "testdata/grey_200x200.jp2")
	require.Equal(t, jp2, portraitForEngine(jp2))
	// JPEG magic that Go cannot decode is left for the engine to judge.
	broken := []byte{0xFF, 0xD8, 0xFF, 0xE0, 1, 2, 3}
	require.Equal(t, broken, portraitForEngine(broken))
}

// The worker hands the engine the transcoded portrait.
func TestWorkerTranscodesJPEGPortrait(t *testing.T) {
	eng := &fakeEngine{}
	src := testJPEG(t, 16, 16, color.RGBA{G: 255, A: 255})
	reply := handleWorkerMessage(eng, pipeMessage{Type: msgPortrait, Payload: []byte(base64.StdEncoding.EncodeToString(src))})
	require.Equal(t, msgState, reply.Type)
	require.Equal(t, "png", portraitFormat(eng.portrait))
}

func testPNG(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, png.Encode(&buf, image.NewGray(image.Rect(0, 0, 8, 8))))
	return buf.Bytes()
}
