package document

import (
	"go-passport-issuer/models"
	"testing"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/stretchr/testify/require"
)

// This test uses DG2 and SOD and Certificate belonging to passport due to no available
// eDL test data, but the EDL passive authentication logic should work for any corresponding DG, SOD and Cert

func createTestEDLRequest() models.ValidationRequest {
	return models.ValidationRequest{
		DataGroups: map[string]string{
			"DG2": dg2Hex,
		},
		EFSOD: testSodHex,
	}
}

func setupEdlVerifyTest(t *testing.T) (models.ValidationRequest, cms.CertPool) {
	t.Helper()
	data := createTestEDLRequest()
	trustedCerts := createTrustedCertPool(t, testCsca)
	return data, trustedCerts
}

func TestPassiveAuthenticationEDL_InvalidInputs(t *testing.T) {
	_, trustedCerts := setupEdlVerifyTest(t)

	for _, tt := range invalidPassiveAuthInput {
		t.Run(tt.name, func(t *testing.T) {
			data := models.ValidationRequest{
				DataGroups: tt.dataGroups,
				EFSOD:      tt.efsod,
			}
			err := PassiveAuthenticationEDL(data, &trustedCerts)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

func TestPassiveAuthenticationEDL_WithRealSOD(t *testing.T) {
	data, trustedCerts := setupEdlVerifyTest(t)

	err := PassiveAuthenticationEDL(data, &trustedCerts)
	require.NoError(t, err)
}
