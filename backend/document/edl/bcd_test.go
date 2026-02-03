package edl

import (
	"testing"
	"time"
)

func TestIsValidBCD(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{"valid all zeros", []byte{0x00, 0x00, 0x00, 0x00}, true},
		{"valid date 17121996", []byte{0x17, 0x12, 0x19, 0x96}, true},
		{"valid date 12072017", []byte{0x12, 0x07, 0x20, 0x17}, true},
		{"invalid high nibble 0xA", []byte{0xA0, 0x01, 0x20, 0x17}, false},
		{"invalid low nibble 0xB", []byte{0x1B, 0x07, 0x20, 0x17}, false},
		{"invalid byte 0x3B (semicolon)", []byte{0x14, 0x07, 0x3B, 0x17}, false},
		{"invalid byte 0xFF", []byte{0xFF, 0xFF, 0xFF, 0xFF}, false},
		{"empty slice", []byte{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidBCD(tt.input)
			if got != tt.want {
				t.Errorf("isValidBCD(%x) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseBCDDate_Valid(t *testing.T) {
	bcd := []byte{0x17, 0x12, 0x19, 0x96}
	got, err := parseBCDDate(bcd)
	if err != nil {
		t.Fatalf("parseBCDDate(%x) returned unexpected error: %v", bcd, err)
	}
	want := time.Date(1996, time.December, 17, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("parseBCDDate(%x) = %v, want %v", bcd, got, want)
	}
}

func TestParseBCDDate_InvalidNibble(t *testing.T) {
	// 0x3B has nibbles 3 and B (11) — B > 9 so it's invalid BCD
	bcd := []byte{0x14, 0x07, 0x3B, 0x17}
	_, err := parseBCDDate(bcd)
	if err == nil {
		t.Fatalf("parseBCDDate(%x) expected error for invalid BCD nibble, got nil", bcd)
	}
}

func TestParseBCDDate_WrongLength(t *testing.T) {
	bcd := []byte{0x17, 0x12, 0x19}
	_, err := parseBCDDate(bcd)
	if err == nil {
		t.Fatalf("parseBCDDate(%x) expected error for wrong length, got nil", bcd)
	}
}
