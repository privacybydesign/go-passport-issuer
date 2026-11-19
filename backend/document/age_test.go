package document

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAgeAttributesCoverOneToNinetyNine(t *testing.T) {
	attributes := AgeAttributes(time.Date(1990, time.June, 15, 0, 0, 0, 0, time.UTC), time.Now())

	require.Len(t, attributes, 99)
	for age := 1; age <= 99; age++ {
		require.Contains(t, attributes, fmt.Sprintf("over%d", age))
	}
	require.NotContains(t, attributes, "over0")
	require.NotContains(t, attributes, "over100")
}

func TestAgeAttributesFollowBirthday(t *testing.T) {
	dateOfBirth := time.Date(2000, time.June, 15, 0, 0, 0, 0, time.UTC)

	dayBefore := AgeAttributes(dateOfBirth, time.Date(2026, time.June, 14, 12, 0, 0, 0, time.UTC))
	require.Equal(t, "Yes", dayBefore["over25"])
	require.Equal(t, "No", dayBefore["over26"])

	onBirthday := AgeAttributes(dateOfBirth, time.Date(2026, time.June, 15, 12, 0, 0, 0, time.UTC))
	require.Equal(t, "Yes", onBirthday["over26"])
	require.Equal(t, "No", onBirthday["over27"])
}

func TestAgeAttributesAreYesBelowAndNoAboveTheAge(t *testing.T) {
	now := time.Date(2026, time.October, 10, 12, 0, 0, 0, time.UTC)
	attributes := AgeAttributes(time.Date(1960, time.January, 1, 0, 0, 0, 0, time.UTC), now)

	for age := 1; age <= 99; age++ {
		want := "No"
		if age <= 66 {
			want = "Yes"
		}
		require.Equal(t, want, attributes[fmt.Sprintf("over%d", age)], "over%d", age)
	}
}

func TestAgeAttributesForNewborn(t *testing.T) {
	now := time.Date(2026, time.October, 10, 12, 0, 0, 0, time.UTC)

	for _, value := range AgeAttributes(now, now) {
		require.Equal(t, "No", value)
	}
}
