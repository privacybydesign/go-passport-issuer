package edl_test

import (
	"encoding/hex"
	"fmt"
	"go-passport-issuer/document/edl"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/stretchr/testify/require"
)

const (
	// Surname:				Bassie
	// First name:			Adriaan
	// Birth day:			17.12.1996
	// Birth place:			Meppel
	// Date of issue:		12.07.2017
	// Date of expiry:		12.07.2017
	// Issuing place:		Gemeente Meppel
	// Document number:		1234567890
	DG_1_TEST = `
		61 818f
			5f01 0d 65342d444c3030203030303031
			5f02 55
				5f03 03 4e4c44
				5f04 06 426173736965
				5f05 06 426172726965
				5f06 04 17121996
				5f07 06 4d657070656c
				5f0a 04 12072017
				5f0b 04 12072027
				5f0c 0f 47656d65656e7465204d657070656c
				5f0e 0a 31323334353637383930
			7f63 24
				02 01 02
				87 0f 414d3b140720173b140720273b3b3b
				87 0e 423b140720173b140720273b3b3b
		`
)

func removeWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1 // drop this rune
		}
		return r
	}, s)
}

func decodeTestCase(t *testing.T, s string) []byte {
	r, err := hex.DecodeString(removeWhitespace(s))
	require.NoError(t, err)
	return r
}

func TestParseEdlDg1(t *testing.T) {
	dg1Bytes := decodeTestCase(t, DG_1_TEST)

	result, err := edl.ParseEDLDG1(dg1Bytes)
	require.NoError(t, err)

	require.Equal(t, result.HolderSurname, "Bassie")
	require.Equal(t, result.HolderOtherName, "Barrie")
	require.Equal(t, result.PlaceOfBirth, "Meppel")
	require.Equal(t, result.IssuingAuthority, "Gemeente Meppel")
	require.Equal(t, result.DocumentNumber, "1234567890")
	require.Equal(t, result.DateOfBirth, time.Date(1996, time.December, 17, 0, 0, 0, 0, time.UTC))
	require.Equal(t, result.DateOfIssue, time.Date(2017, time.July, 12, 0, 0, 0, 0, time.UTC))
	require.Equal(t, result.DateOfExpiry, time.Date(2027, time.July, 12, 0, 0, 0, 0, time.UTC))
}
