package edl

import (
	"testing"
	"time"
)

func TestParseBCDDate(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    time.Time
		wantErr bool
	}{
		{"valid date 17121996", []byte{0x17, 0x12, 0x19, 0x96}, time.Date(1996, time.December, 17, 0, 0, 0, 0, time.UTC), false},
		{"valid date 12072017", []byte{0x12, 0x07, 0x20, 0x17}, time.Date(2017, time.July, 12, 0, 0, 0, 0, time.UTC), false},
		{"valid all zeros", []byte{0x00, 0x00, 0x00, 0x00}, time.Date(0, 0, 0, 0, 0, 0, 0, time.UTC), false},
		{"invalid high nibble 0xA", []byte{0xA0, 0x01, 0x20, 0x17}, time.Time{}, true},
		{"invalid low nibble 0xB", []byte{0x1B, 0x07, 0x20, 0x17}, time.Time{}, true},
		{"invalid byte 0x3B", []byte{0x14, 0x07, 0x3B, 0x17}, time.Time{}, true},
		{"invalid byte 0xFF", []byte{0xFF, 0xFF, 0xFF, 0xFF}, time.Time{}, true},
		{"wrong length 3 bytes", []byte{0x17, 0x12, 0x19}, time.Time{}, true},
		{"empty slice", []byte{}, time.Time{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseBCDDate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseBCDDate(%x) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && !got.Equal(tt.want) {
				t.Errorf("parseBCDDate(%x) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
