package document

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const TEST_MONTHDATE = "0101"

func TestBoolToYesNo(t *testing.T) {
	t.Run("true converts to Yes", func(t *testing.T) {
		result := BoolToYesNo(true)
		require.Equal(t, "Yes", result)
	})

	t.Run("false converts to No", func(t *testing.T) {
		result := BoolToYesNo(false)
		require.Equal(t, "No", result)
	})
}

func TestParseExpiryDate(t *testing.T) {
	t.Run("valid date parses correctly", func(t *testing.T) {
		result, err := ParseExpiryDate("250315")
		require.NoError(t, err)
		require.Equal(t, 2025, result.Year())
		require.Equal(t, time.March, result.Month())
		require.Equal(t, 15, result.Day())
	})

	t.Run("one year after current year doesn't get 100 subtracted", func(t *testing.T) {
		now := time.Now()
		nextYear := now.Year()%100 + 1
		result, err := ParseExpiryDate(fmt.Sprintf("%v%s", nextYear, TEST_MONTHDATE))
		require.NoError(t, err)
		require.Equal(t, result.Year(), now.Year()+1)
		require.Equal(t, result.Month(), time.January)
		require.Equal(t, result.Day(), 1)
	})

	t.Run("30 years before now year get 100 years added", func(t *testing.T) {
		thirtyYearsAgo := time.Now().AddDate(-30, 0, 0)
		thirtyYearsAgoMod := thirtyYearsAgo.Year() % 100
		result, err := ParseExpiryDate(fmt.Sprintf("%v%s", thirtyYearsAgoMod, TEST_MONTHDATE))
		require.NoError(t, err)
		require.Equal(t, result.Year(), thirtyYearsAgo.Year()+100)
		require.Equal(t, result.Month(), time.January)
		require.Equal(t, result.Day(), 1)
	})

	t.Run("29 years before now is untouched", func(t *testing.T) {
		thirtyYearsAgo := time.Now().AddDate(-29, 0, 0)
		thirtyYearsAgoMod := thirtyYearsAgo.Year() % 100
		result, err := ParseExpiryDate(fmt.Sprintf("%v%s", thirtyYearsAgoMod, TEST_MONTHDATE))
		require.NoError(t, err)
		require.Equal(t, result.Year(), thirtyYearsAgo.Year())
		require.Equal(t, result.Month(), time.January)
		require.Equal(t, result.Day(), 1)
	})

	t.Run("30 years after now is untouched", func(t *testing.T) {
		thirtyYearsFromNow := time.Now().AddDate(30, 0, 0)
		thirtyYearsFromNowMod := thirtyYearsFromNow.Year() % 100
		result, err := ParseExpiryDate(fmt.Sprintf("%v%s", thirtyYearsFromNowMod, TEST_MONTHDATE))
		require.NoError(t, err)
		require.Equal(t, result.Year(), thirtyYearsFromNow.Year())
		require.Equal(t, result.Month(), time.January)
		require.Equal(t, result.Day(), 1)
	})

	// the limit for the Go time parser is 1969
	t.Run("68 parses as 1968", func(t *testing.T) {
		result, err := ParseExpiryDate("680101")
		require.NoError(t, err)
		require.Equal(t, 2068, result.Year())
		require.Equal(t, time.January, result.Month())
		require.Equal(t, 1, result.Day())
	})

	// the limit for the Go time parser is 1969
	t.Run("69 parses as 2069", func(t *testing.T) {
		result, err := ParseExpiryDate("690101")
		require.NoError(t, err)
		require.Equal(t, 2069, result.Year())
		require.Equal(t, time.January, result.Month())
		require.Equal(t, 1, result.Day())
	})

	t.Run("invalid format - too short", func(t *testing.T) {
		_, err := ParseExpiryDate("25031")
		requireInvalidDateException(t, err)
	})

	t.Run("invalid format - too long", func(t *testing.T) {
		_, err := ParseExpiryDate("2503155")
		requireInvalidDateException(t, err)
	})

	t.Run("invalid date values", func(t *testing.T) {
		_, err := ParseExpiryDate("251399")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error parsing date")
	})

	t.Run("empty string", func(t *testing.T) {
		_, err := ParseExpiryDate("")
		requireInvalidDateException(t, err)
	})
}

func TestParseDateOfBirth(t *testing.T) {
	t.Run("valid date parses correctly", func(t *testing.T) {
		result, err := ParseDateOfBirth("250315")
		require.NoError(t, err)
		require.Equal(t, 2025, result.Year())
		require.Equal(t, time.March, result.Month())
		require.Equal(t, 15, result.Day())
	})

	t.Run("one year after current year gets 100 subtracted", func(t *testing.T) {
		nextYear := time.Now().Year()%100 + 1
		result, err := ParseDateOfBirth(fmt.Sprintf("%v%s", nextYear, TEST_MONTHDATE))
		require.NoError(t, err)
		require.Equal(t, result.Year(), nextYear+1900)
		require.Equal(t, result.Month(), time.January)
		require.Equal(t, result.Day(), 1)
	})

	t.Run("current year doesn't get 100 subtracted", func(t *testing.T) {
		currYear := time.Now().Year() % 100
		result, err := ParseDateOfBirth(fmt.Sprintf("%v%s", currYear, TEST_MONTHDATE))
		require.NoError(t, err)
		require.Equal(t, result.Year(), time.Now().Year())
		require.Equal(t, result.Month(), time.January)
		require.Equal(t, result.Day(), 1)
	})

	t.Run("one year before current year doesn't get 100 subtracted", func(t *testing.T) {
		lastYear := time.Now().Year()%100 - 1
		result, err := ParseDateOfBirth(fmt.Sprintf("%v%s", lastYear, TEST_MONTHDATE))
		require.NoError(t, err)
		require.Equal(t, result.Year(), time.Now().Year()-1)
		require.Equal(t, result.Month(), time.January)
		require.Equal(t, result.Day(), 1)
	})

	// the limit for the Go time parser is 1969
	t.Run("1968 parses correctly", func(t *testing.T) {
		result, err := ParseDateOfBirth("680101")
		require.NoError(t, err)
		require.Equal(t, 1968, result.Year())
		require.Equal(t, time.January, result.Month())
		require.Equal(t, 1, result.Day())
	})

	// the limit for the Go time parser is 1969
	t.Run("1969 parses correctly", func(t *testing.T) {
		result, err := ParseDateOfBirth("690101")
		require.NoError(t, err)
		require.Equal(t, 1969, result.Year())
		require.Equal(t, time.January, result.Month())
		require.Equal(t, 1, result.Day())
	})

	t.Run("another valid date", func(t *testing.T) {
		result, err := ParseDateOfBirth("990101")
		require.NoError(t, err)
		require.Equal(t, 1999, result.Year())
		require.Equal(t, time.January, result.Month())
		require.Equal(t, 1, result.Day())
	})

	t.Run("invalid format - too short", func(t *testing.T) {
		_, err := ParseDateOfBirth("25031")
		requireInvalidDateException(t, err)
	})

	t.Run("invalid format - too long", func(t *testing.T) {
		_, err := ParseDateOfBirth("2503155")
		requireInvalidDateException(t, err)
	})

	t.Run("invalid date values", func(t *testing.T) {
		_, err := ParseDateOfBirth("251399")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error parsing date")
	})

	t.Run("empty string", func(t *testing.T) {
		_, err := ParseDateOfBirth("")
		requireInvalidDateException(t, err)
	})
}

func requireInvalidDateException(t *testing.T, err error) {
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid date format")
}
