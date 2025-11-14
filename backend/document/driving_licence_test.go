package document

import (
	"go-passport-issuer/models"
	"testing"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/stretchr/testify/require"
)

// This test uses DG2 and SOD and Certificate belonging to passport due to no available
// eDL test data

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
	tests := []struct {
		name             string
		dataGroups       map[string]string
		efsod            string
		passportCertPool *cms.CombinedCertPool
		expectedError    string
	}{
		{
			name:             "empty data groups returns error",
			dataGroups:       map[string]string{},
			efsod:            "some_sod_data",
			passportCertPool: nil,
			expectedError:    "no data groups found",
		},
		{
			name: "missing EF_SOD returns error",
			dataGroups: map[string]string{
				"DG1": "some_data",
			},
			efsod:            "",
			passportCertPool: nil,
			expectedError:    "EF_SOD is missing",
		},
		{
			name: "invalid SOD returns error",
			dataGroups: map[string]string{
				"DG1": "some_data",
			},
			efsod:            "AABBCC",
			passportCertPool: &cms.CombinedCertPool{},
			expectedError:    "failed to create SOD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := models.ValidationRequest{
				DataGroups: tt.dataGroups,
				EFSOD:      tt.efsod,
			}
			err := PassiveAuthenticationEDL(data, tt.passportCertPool)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

func TestPassiveAuthenticationEDL_WithRealSOD(t *testing.T) {
	data, trustedCerts := setupEdlVerifyTest(t)

	err := PassiveAuthenticationEDL(data, trustedCerts)
	require.NoError(t, err)
}
