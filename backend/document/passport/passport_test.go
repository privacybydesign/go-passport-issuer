package passport

import (
	"fmt"
	"go-passport-issuer/models"
	"testing"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/mrz"
	"github.com/gmrtd/gmrtd/utils"
	"github.com/stretchr/testify/require"
)

func requireDataGroupIsNil(t *testing.T, doc document.Document, dataGroupName string) {
	dataGroups := map[string]interface{}{
		"DG11": doc.Mf.Lds1.Dg11,
		"DG12": doc.Mf.Lds1.Dg12,
		"DG13": doc.Mf.Lds1.Dg13,
		"DG14": doc.Mf.Lds1.Dg14,
		"DG16": doc.Mf.Lds1.Dg16,
	}
	require.Nil(t, dataGroups[dataGroupName], "expected %s to be nil", dataGroupName)
}

func requireErrorContains(t *testing.T, err error, expectedMsg string) {
	t.Helper()
	require.Error(t, err)
	require.Contains(t, err.Error(), expectedMsg)
}

func createTestPassportRequest() models.ValidationRequest {
	return models.ValidationRequest{
		DataGroups: map[string]string{
			"DG1": TestDg1Hex,
			"DG2": Dg2Hex,
		},
		EFSOD: TestSodHex,
	}
}

func setupPassportAuthTest(t *testing.T) (models.ValidationRequest, cms.CertPool) {
	t.Helper()
	data := createTestPassportRequest()
	trustedCerts := CreateTrustedCertPool(t, TestCsca)
	return data, trustedCerts
}

func TestIsEuCitizen(t *testing.T) {
	t.Run("valid EU country uppercase", func(t *testing.T) {
		require.True(t, IsEuCitizen("NLD"))
		require.True(t, IsEuCitizen("D"))
		require.True(t, IsEuCitizen("FRA"))
		require.True(t, IsEuCitizen("ESP"))
		require.True(t, IsEuCitizen("ITA"))
	})

	t.Run("valid EU country lowercase", func(t *testing.T) {
		require.True(t, IsEuCitizen("nld"))
		require.True(t, IsEuCitizen("d"))
		require.True(t, IsEuCitizen("fra"))
	})

	t.Run("valid EU country mixed case", func(t *testing.T) {
		require.True(t, IsEuCitizen("Nld"))
		require.True(t, IsEuCitizen("D"))
	})

	t.Run("non-EU country", func(t *testing.T) {
		require.False(t, IsEuCitizen("USA"))
		require.False(t, IsEuCitizen("GBR"))
		require.False(t, IsEuCitizen("CHE"))
		require.False(t, IsEuCitizen("NOR"))
	})

	t.Run("empty string", func(t *testing.T) {
		require.False(t, IsEuCitizen(""))
	})

	t.Run("Germany exception - D instead of DEU", func(t *testing.T) {
		// Germany uses "D" as the country code instead of the expected "DEU"
		require.True(t, IsEuCitizen("D"))
		require.True(t, IsEuCitizen("d"))
		// DEU should not be recognized since Germany uses "D"
		require.False(t, IsEuCitizen("DEU"))
	})

	t.Run("all EU countries", func(t *testing.T) {
		euCountries := []string{
			"AUT", "BEL", "BGR", "HRV", "CYP",
			"CZE", "DNK", "EST", "FIN", "FRA",
			"D", "GRC", "HUN", "IRL", "ITA",
			"LVA", "LTU", "LUX", "MLT", "NLD",
			"POL", "PRT", "ROU", "SVK", "SVN",
			"ESP", "SWE",
		}
		for _, country := range euCountries {
			require.True(t, IsEuCitizen(country), "Country %s should be recognized as EU", country)
		}
	})
}

func TestPassiveAuthenticationPassport(t *testing.T) {

	for _, tt := range InvalidPassiveAuthInput {
		t.Run(tt.Name, func(t *testing.T) {
			data := models.ValidationRequest{
				DataGroups: tt.DataGroups,
				EFSOD:      tt.Efsod,
			}
			_, err := PassiveAuthenticationPassport(data, tt.PassportCertPool)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.ExpectedError)
		})
	}
}

func TestPassiveAuthenticationPassportWithRealSOD(t *testing.T) {
	// Test that PassiveAuthenticationPassport can parse real SOD data from gmrtd test cases
	// based on an expired UK passport
	// Source: https://github.com/gmrtd/gmrtd/blob/main/passiveauth/passive_auth_test.go

	data, trustedCerts := setupPassportAuthTest(t)

	// Test that SOD can be parsed correctly and that passive auth works.
	_, err := PassiveAuthenticationPassport(data, trustedCerts)
	require.NoError(t, err)
}

func TestPassiveAuthenticationPassportIgnoresInvalidDG7(t *testing.T) {
	data, trustedCerts := setupPassportAuthTest(t)
	data.DataGroups["DG7"] = "00"

	doc, err := PassiveAuthenticationPassport(data, trustedCerts)
	require.NoError(t, err)
	require.Nil(t, doc.Mf.Lds1.Dg7)
}

func TestActiveAuthenticationPassport(t *testing.T) {

	for _, tt := range InvalidActiveAuthInput {
		t.Run(tt.Name, func(t *testing.T) {
			data := models.ValidationRequest{
				Nonce:               tt.Nonce,
				ActiveAuthSignature: tt.Signature,
			}
			doc := document.Document{}
			result, err := ActiveAuthentication(data, doc)
			require.NoError(t, err)
			require.False(t, result)
		})
	}
}

func TestActiveAuthentication_InvalidSignature(t *testing.T) {
	// Test with DG15 present but invalid Signature
	var dg15Hex = "6F81A130819E300D06092A864886F70D010101050003818C00308188028180CF9A8BA6EAD230E592AA6B5DA04558CC005A5291B295418575D68D637F41AF105813293D1D43F3685F014FFF3007730E6A15B7801558C6911F1084B7B8553BEE577F84EA7B8BF346128DA380D57E500FAF5AB70971DD9B25F387343E0B6CFA1316B3F58F6B9D3E93A72DD6BE3C7A79D960CE8CBAF8726F5E4FBF289287941FD70203010001"
	dg15Bytes := utils.HexToBytes(dg15Hex)
	dg15, err := document.NewDG15(dg15Bytes)
	require.NoError(t, err)

	doc := document.Document{}
	doc.Mf.Lds1.Dg15 = dg15

	data := models.ValidationRequest{
		Nonce:               "AABBCCDD",
		ActiveAuthSignature: "DEADBEEF",
	}

	result, err := ActiveAuthentication(data, doc)
	require.Error(t, err)
	require.False(t, result)
	require.Contains(t, err.Error(), "failed to validate active authentication signature")
}

func TestActiveAuthentication_ValidationHashMismatch(t *testing.T) {
	// Test with DG15 present and properly formatted signature structure, but validation fails due to hash mismatch
	// This tests the case where the signature can be decrypted but the hash doesn't match the nonce
	// Note: In practice, ValidateActiveAuthSignature returns an error (not just Success=false) when validation fails
	var dg15Hex = "6F81A130819E300D06092A864886F70D010101050003818C00308188028180CF9A8BA6EAD230E592AA6B5DA04558CC005A5291B295418575D68D637F41AF105813293D1D43F3685F014FFF3007730E6A15B7801558C6911F1084B7B8553BEE577F84EA7B8BF346128DA380D57E500FAF5AB70971DD9B25F387343E0B6CFA1316B3F58F6B9D3E93A72DD6BE3C7A79D960CE8CBAF8726F5E4FBF289287941FD70203010001"
	dg15Bytes := utils.HexToBytes(dg15Hex)
	dg15, err := document.NewDG15(dg15Bytes)
	require.NoError(t, err)

	doc := document.Document{}
	doc.Mf.Lds1.Dg15 = dg15

	// Create a properly sized signature (128 bytes = 256 hex chars) that will parse but fail hash validation
	invalidSignature := "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"

	data := models.ValidationRequest{
		Nonce:               "AABBCCDD",
		ActiveAuthSignature: invalidSignature,
	}

	result, err := ActiveAuthentication(data, doc)
	require.Error(t, err)
	require.False(t, result)
	// The error is from ValidateActiveAuthSignature, which returns an error on validation failure
	require.Contains(t, err.Error(), "failed to validate active authentication signature")
}

func TestPassiveAuthenticationIgnoresInvalidOptionalDataGroups(t *testing.T) {
	invalidDataGroupHex := "00"

	testCases := []struct {
		dataGroupName string
		dataGroupHex  string
	}{
		{"DG11", invalidDataGroupHex},
		{"DG12", invalidDataGroupHex},
		{"DG13", invalidDataGroupHex},
		{"DG14", invalidDataGroupHex},
		{"DG16", invalidDataGroupHex},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("invalid %s is ignored gracefully", tc.dataGroupName), func(t *testing.T) {
			data, trustedCerts := setupPassportAuthTest(t)
			data.DataGroups[tc.dataGroupName] = tc.dataGroupHex

			doc, err := PassiveAuthenticationPassport(data, trustedCerts)
			require.NoError(t, err, "should not fail when %s is invalid", tc.dataGroupName)

			// Verify that the invalid data group was not set
			requireDataGroupIsNil(t, doc, tc.dataGroupName)
		})
	}
}

func TestPassiveAuthenticationMandatoryDataGroups(t *testing.T) {
	t.Run("invalid DG1 fails", func(t *testing.T) {
		data := models.ValidationRequest{
			DataGroups: map[string]string{
				"DG1": "00",
			},
			EFSOD: TestSodHex,
		}

		trustedCerts := CreateTrustedCertPool(t, TestCsca)

		_, err := PassiveAuthenticationPassport(data, trustedCerts)
		requireErrorContains(t, err, "failed to create DG1 (mandatory)")
	})

	t.Run("invalid DG2 fails", func(t *testing.T) {
		data, trustedCerts := setupPassportAuthTest(t)
		data.DataGroups["DG2"] = "00"

		_, err := PassiveAuthenticationPassport(data, trustedCerts)
		requireErrorContains(t, err, "failed to create DG2 (mandatory)")
	})

	t.Run("invalid DG15 fails if provided", func(t *testing.T) {
		data, trustedCerts := setupPassportAuthTest(t)
		delete(data.DataGroups, "DG2")
		data.DataGroups["DG15"] = "00"

		_, err := PassiveAuthenticationPassport(data, trustedCerts)
		requireErrorContains(t, err, "failed to create DG15 (mandatory if provided)")
	})

	t.Run("missing DG1 fails", func(t *testing.T) {
		data := models.ValidationRequest{
			DataGroups: map[string]string{
				// DG1 is missing, but we include DG7 to get past the empty check
				"DG7": "675A3158561234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
			},
			EFSOD: TestSodHex,
		}

		trustedCerts := CreateTrustedCertPool(t, TestCsca)

		_, err := PassiveAuthenticationPassport(data, trustedCerts)
		requireErrorContains(t, err, "DG1 is mandatory but was not provided")
	})

	t.Run("missing DG2 fails", func(t *testing.T) {
		data, trustedCerts := setupPassportAuthTest(t)
		delete(data.DataGroups, "DG2")

		_, err := PassiveAuthenticationPassport(data, trustedCerts)
		requireErrorContains(t, err, "DG2 is mandatory but was not provided")
	})
}

func TestNormalizeSex(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Standard male/female values
		{"male uppercase", "M", "M"},
		{"male lowercase", "m", "M"},
		{"female uppercase", "F", "F"},
		{"female lowercase", "f", "F"},

		// Non-binary/unspecified values
		{"X uppercase (non-binary)", "X", "X"},
		{"x lowercase (non-binary)", "x", "X"},
		{"< filler character (ICAO unspecified)", "<", "X"},

		// Unknown/edge cases - should return X
		{"empty string", "", "X"},
		{"unknown value", "U", "X"},
		{"random character", "?", "X"},
		{"multiple characters", "MF", "X"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeSex(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractNames(t *testing.T) {
	// Create a base document with DG1 data
	createBaseDoc := func() document.Document {
		dg1Bytes := utils.HexToBytes(TestDg1Hex)
		dg1, err := document.NewDG1(dg1Bytes)
		require.NoError(t, err)

		doc := document.Document{}
		doc.Mf.Lds1.Dg1 = dg1
		return doc
	}

	t.Run("fallback to DG1 when DG11 is nil", func(t *testing.T) {
		doc := createBaseDoc()
		doc.Mf.Lds1.Dg11 = nil

		firstName, lastName := extractNames(doc)

		// DG1 contains MRZ names (from test data: SANDERSON<<OSCAR<CHARLES<EDWARD)
		require.Equal(t, "OSCAR CHARLES EDWARD", firstName)
		require.Equal(t, "SANDERSON", lastName)
	})

	t.Run("fallback to DG1 when DG11 NameOfHolder is nil", func(t *testing.T) {
		doc := createBaseDoc()
		doc.Mf.Lds1.Dg11 = &document.DG11{
			Details: document.PersonDetails{
				NameOfHolder: nil,
			},
		}

		firstName, lastName := extractNames(doc)

		require.Equal(t, "OSCAR CHARLES EDWARD", firstName)
		require.Equal(t, "SANDERSON", lastName)
	})

	t.Run("fallback to DG1 when DG11 names are empty", func(t *testing.T) {
		doc := createBaseDoc()
		doc.Mf.Lds1.Dg11 = &document.DG11{
			Details: document.PersonDetails{
				NameOfHolder: &mrz.MrzName{
					Primary:   "",
					Secondary: "",
				},
			},
		}

		firstName, lastName := extractNames(doc)

		require.Equal(t, "OSCAR CHARLES EDWARD", firstName)
		require.Equal(t, "SANDERSON", lastName)
	})

	t.Run("use DG11 when available with diacritics", func(t *testing.T) {
		doc := createBaseDoc()
		doc.Mf.Lds1.Dg11 = &document.DG11{
			Details: document.PersonDetails{
				NameOfHolder: &mrz.MrzName{
					Primary:   "Jovanović",
					Secondary: "Miloš",
				},
			},
		}

		firstName, lastName := extractNames(doc)

		// DG11 names with diacritics should be used
		require.Equal(t, "Miloš", firstName)
		require.Equal(t, "Jovanović", lastName)
	})

	t.Run("use DG11 when only primary name is present", func(t *testing.T) {
		doc := createBaseDoc()
		doc.Mf.Lds1.Dg11 = &document.DG11{
			Details: document.PersonDetails{
				NameOfHolder: &mrz.MrzName{
					Primary:   "Müller",
					Secondary: "",
				},
			},
		}

		firstName, lastName := extractNames(doc)

		// Should use DG11 since Primary is non-empty
		require.Equal(t, "", firstName)
		require.Equal(t, "Müller", lastName)
	})

	t.Run("use DG11 when only secondary name is present", func(t *testing.T) {
		doc := createBaseDoc()
		doc.Mf.Lds1.Dg11 = &document.DG11{
			Details: document.PersonDetails{
				NameOfHolder: &mrz.MrzName{
					Primary:   "",
					Secondary: "José",
				},
			},
		}

		firstName, lastName := extractNames(doc)

		// Should use DG11 since Secondary is non-empty
		require.Equal(t, "José", firstName)
		require.Equal(t, "", lastName)
	})

	t.Run("DG11 with special characters", func(t *testing.T) {
		doc := createBaseDoc()
		doc.Mf.Lds1.Dg11 = &document.DG11{
			Details: document.PersonDetails{
				NameOfHolder: &mrz.MrzName{
					Primary:   "Østerberg",
					Secondary: "Björk Guðmundsdóttir",
				},
			},
		}

		firstName, lastName := extractNames(doc)

		require.Equal(t, "Björk Guðmundsdóttir", firstName)
		require.Equal(t, "Østerberg", lastName)
	})
}

func TestToPassportData(t *testing.T) {
	// Helper to create a complete document with DG1 and DG2
	createCompleteDoc := func(t *testing.T) document.Document {
		dg1Bytes := utils.HexToBytes(TestDg1Hex)
		dg1, err := document.NewDG1(dg1Bytes)
		require.NoError(t, err)

		dg2Bytes := utils.HexToBytes(Dg2Hex)
		dg2, err := document.NewDG2(dg2Bytes)
		require.NoError(t, err)

		doc := document.Document{}
		doc.Mf.Lds1.Dg1 = dg1
		doc.Mf.Lds1.Dg2 = dg2
		return doc
	}

	t.Run("uses DG1 names when DG11 is not present", func(t *testing.T) {
		doc := createCompleteDoc(t)

		passportData, err := ToPassportData(doc, false)
		require.NoError(t, err)

		// Names from DG1 MRZ (SANDERSON<<OSCAR<CHARLES<EDWARD)
		require.Equal(t, "OSCAR CHARLES EDWARD", passportData.FirstName)
		require.Equal(t, "SANDERSON", passportData.LastName)
	})

	t.Run("uses DG11 names with diacritics when available", func(t *testing.T) {
		doc := createCompleteDoc(t)
		doc.Mf.Lds1.Dg11 = &document.DG11{
			Details: document.PersonDetails{
				NameOfHolder: &mrz.MrzName{
					Primary:   "Jovanović",
					Secondary: "Miloš",
				},
			},
		}

		passportData, err := ToPassportData(doc, false)
		require.NoError(t, err)

		// DG11 names should be used
		require.Equal(t, "Miloš", passportData.FirstName)
		require.Equal(t, "Jovanović", passportData.LastName)
	})

	t.Run("normalizes male sex to M", func(t *testing.T) {
		doc := createCompleteDoc(t)
		// The test DG1 has "M" as sex

		passportData, err := ToPassportData(doc, false)
		require.NoError(t, err)

		require.Equal(t, "M", passportData.Gender)
	})

	t.Run("includes photo from DG2", func(t *testing.T) {
		doc := createCompleteDoc(t)

		passportData, err := ToPassportData(doc, false)
		require.NoError(t, err)

		require.NotEmpty(t, passportData.Photo)
	})

	t.Run("sets active authentication correctly", func(t *testing.T) {
		doc := createCompleteDoc(t)

		passportDataWithAA, err := ToPassportData(doc, true)
		require.NoError(t, err)
		require.Equal(t, "Yes", passportDataWithAA.ActiveAuthentication)

		passportDataWithoutAA, err := ToPassportData(doc, false)
		require.NoError(t, err)
		require.Equal(t, "No", passportDataWithoutAA.ActiveAuthentication)
	})

	t.Run("extracts document metadata correctly", func(t *testing.T) {
		doc := createCompleteDoc(t)

		passportData, err := ToPassportData(doc, false)
		require.NoError(t, err)

		// From test DG1: P<GBR (passport, UK)
		require.Equal(t, "P", passportData.DocumentType)
		require.Equal(t, "GBR", passportData.Country)
		require.Equal(t, "GBR", passportData.Nationality)
		require.Equal(t, "No", passportData.IsEuCitizen) // GBR is not EU
	})
}
