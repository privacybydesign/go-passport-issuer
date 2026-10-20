package main

import (
	"bytes"
	"encoding/base64"
	"image/jpeg"
	"image/png"
)

// portraitFormat names a portrait's image format from its magic bytes, for
// logs. It reads nothing beyond the signature, so it reveals nothing about
// the face.
func portraitFormat(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte{0xFF, 0xD8, 0xFF}):
		return "jpeg"
	case bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")):
		return "png"
	case bytes.HasPrefix(b, []byte{0, 0, 0, 0x0C, 'j', 'P', ' ', ' ', 0x0D, 0x0A, 0x87, 0x0A}):
		return "jp2"
	case bytes.HasPrefix(b, []byte{0xFF, 0x4F, 0xFF, 0x51}):
		return "j2k"
	}
	return "unknown"
}

// portraitFormatOfBase64 is portraitFormat for the base64 form the parent
// holds; it decodes only the first 12 bytes.
func portraitFormatOfBase64(s string) string {
	if len(s) > 16 {
		s = s[:16]
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "unknown"
	}
	return portraitFormat(b)
}

// portraitForEngine works around libpassportreader-20261002, which refuses
// every JPEG portrait in initiate while accepting the same image as PNG or
// JPEG 2000; the drop before it read JPEG fine. Chip portraits are JPEG on
// driving licences and on some passports, so a JPEG is re-encoded as PNG,
// losslessly from the decoded pixels. Anything else, and a JPEG Go cannot
// decode, is passed through for the engine to judge.
//
// The issuer binds the session to the hash of the original bytes, which the
// parent checked at creation; this only changes what the engine is handed.
// Remove it once a vendor drop decodes JPEG again: the smoke test logs
// whether the engine accepts a JPEG portrait directly.
func portraitForEngine(portrait []byte) []byte {
	if portraitFormat(portrait) != "jpeg" {
		return portrait
	}
	img, err := jpeg.Decode(bytes.NewReader(portrait))
	if err != nil {
		return portrait
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return portrait
	}
	return buf.Bytes()
}
