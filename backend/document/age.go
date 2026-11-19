package document

import (
	"fmt"
	"time"
)

const (
	MinAgeThreshold = 1
	MaxAgeThreshold = 99
)

// AgeAttributes returns the over1 … over99 attributes of the age credential:
// "Yes" when someone born on dateOfBirth is at least that old at now.
func AgeAttributes(dateOfBirth, now time.Time) map[string]string {
	attributes := make(map[string]string, MaxAgeThreshold-MinAgeThreshold+1)

	for age := MinAgeThreshold; age <= MaxAgeThreshold; age++ {
		attributes[fmt.Sprintf("over%d", age)] = BoolToYesNo(dateOfBirth.Before(now.AddDate(-age, 0, 0)))
	}

	return attributes
}
