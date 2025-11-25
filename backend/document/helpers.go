package document

import (
	"fmt"
	"time"
)

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
