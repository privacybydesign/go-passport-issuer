package images

import (
	"encoding/base64"
	"testing"

	"github.com/gmrtd/gmrtd/document"
)

func TestRawDG2ImageBase64(t *testing.T) {
	raw := []byte{0x01, 0x02, 0x03, 0x04}
	dg2 := &document.DG2{Images: []document.DG2Image{{Image: raw}}}

	got, err := RawDG2ImageBase64(dg2)
	if err != nil {
		t.Fatalf("RawDG2ImageBase64 returned error: %v", err)
	}
	if want := base64.StdEncoding.EncodeToString(raw); got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestRawDG2ImageBase64_Nil(t *testing.T) {
	if _, err := RawDG2ImageBase64(nil); err == nil {
		t.Error("expected error for nil DG2")
	}
}

func TestRawDG2ImageBase64_NoImages(t *testing.T) {
	if _, err := RawDG2ImageBase64(&document.DG2{}); err == nil {
		t.Error("expected error for DG2 without images")
	}
	empty := &document.DG2{Images: []document.DG2Image{{Image: nil}}}
	if _, err := RawDG2ImageBase64(empty); err == nil {
		t.Error("expected error for DG2 with empty image bytes")
	}
}

func TestImageContainer_RawBase64(t *testing.T) {
	raw := []byte{0xAA, 0xBB, 0xCC}
	ic := &ImageContainer{ImageData: raw}

	got, err := ic.RawBase64()
	if err != nil {
		t.Fatalf("RawBase64 returned error: %v", err)
	}
	if want := base64.StdEncoding.EncodeToString(raw); got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestImageContainer_RawBase64_Empty(t *testing.T) {
	ic := &ImageContainer{}
	if _, err := ic.RawBase64(); err == nil {
		t.Error("expected error for empty image data")
	}
}
