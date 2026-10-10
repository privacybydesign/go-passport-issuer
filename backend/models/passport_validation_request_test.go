package models

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIssuanceScope(t *testing.T) {
	testCases := []struct {
		scope           IssuanceScope
		valid           bool
		includesDoc     bool
		includesAgeCred bool
	}{
		{scope: "", valid: true, includesDoc: true, includesAgeCred: false},
		{scope: IssueDocument, valid: true, includesDoc: true, includesAgeCred: false},
		{scope: IssueDocumentAndAge, valid: true, includesDoc: true, includesAgeCred: true},
		{scope: IssueAgeOnly, valid: true, includesDoc: false, includesAgeCred: true},
		{scope: "everything", valid: false, includesDoc: true, includesAgeCred: false},
	}

	for _, tc := range testCases {
		t.Run(string(tc.scope), func(t *testing.T) {
			require.Equal(t, tc.valid, tc.scope.Valid())
			require.Equal(t, tc.includesDoc, tc.scope.IncludesDocument())
			require.Equal(t, tc.includesAgeCred, tc.scope.IncludesAge())
		})
	}
}
