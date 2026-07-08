package document

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"
)

// ErrActiveAuthRequired is returned when a document chip advertises an Active
// Authentication key but the request did not include the nonce/signature needed
// to perform the challenge-response. Active Authentication is mandatory whenever
// the chip supports it, so this condition rejects issuance rather than falling
// through to a credential with activeAuthentication = "No".
var ErrActiveAuthRequired = errors.New("active authentication required for this document")

// SodFingerprint returns identifying info about an SOD byte slice for
// triage logging: total length, SHA-256, and the hex of the first up-to-32
// bytes (enough to see the TLV root tag, typically 0x77 for a valid SOD).
func SodFingerprint(sod []byte) (length int, sha256Hex string, headHex string) {
	sum := sha256.Sum256(sod)
	head := sod
	if len(head) > 32 {
		head = head[:32]
	}
	return len(sod), hex.EncodeToString(sum[:]), hex.EncodeToString(head)
}

// DataGroupInventory returns a sorted list of "DGn(byteLen)" strings derived
// from a hex-encoded data-group map. Useful to spot wrong-file uploads.
func DataGroupInventory(dgs map[string]string) []string {
	out := make([]string, 0, len(dgs))
	for name, hexStr := range dgs {
		out = append(out, fmt.Sprintf("%s(%d)", name, len(hexStr)/2))
	}
	sort.Strings(out)
	return out
}

func BoolToYesNo(value bool) string {
	if value {
		return "Yes"
	}
	return "No"
}

func ParseExpiryDate(dateStr string) (time.Time, error) {
	// Parse date in yymmdd format
	if len(dateStr) != 6 {
		return time.Time{}, fmt.Errorf("invalid date format: %s", dateStr)
	}
	layout := "060102" // "06" for year, "01" for month, "02" for day

	parsedDate, err := time.Parse(layout, dateStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("error parsing date: %w", err)
	}

	// arbitrarily determine that a date more than 30 years ago
	// gets added 100 years
	if parsedDate.Before(time.Now().AddDate(-30, 0, 0)) {
		parsedDate = parsedDate.AddDate(100, 0, 0)
	}

	return parsedDate, nil
}

func ParseDateOfBirth(dateStr string) (time.Time, error) {
	// Parse date in yymmdd format
	if len(dateStr) != 6 {
		return time.Time{}, fmt.Errorf("invalid date format: %s", dateStr)
	}
	layout := "060102" // "06" for year, "01" for month, "02" for day

	parsedDate, err := time.Parse(layout, dateStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("error parsing date: %w", err)
	}

	// Dates are stored in passports with only two digits for the year,
	// so when someone is born in 1950, only the 50 part is stored.
	// The Go time parser turns this into 2050 for some reason.
	// To combat this we determine if the (parsed) birth year is higher than the current year.
	// If it is we'll subtract 100 years from it.
	if parsedDate.After(time.Now()) {
		parsedDate = parsedDate.AddDate(-100, 0, 0)
	}

	return parsedDate, nil
}
