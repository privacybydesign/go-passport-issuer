package passport

import (
	"go-passport-issuer/models"
	"testing"
	"time"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/stretchr/testify/require"
)

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

func TestParseDateTime(t *testing.T) {
	t.Run("valid date parses correctly", func(t *testing.T) {
		result, err := ParseDateTime("250315")
		require.NoError(t, err)
		require.Equal(t, 2025, result.Year())
		require.Equal(t, time.March, result.Month())
		require.Equal(t, 15, result.Day())
	})

	t.Run("another valid date", func(t *testing.T) {
		result, err := ParseDateTime("990101")
		require.NoError(t, err)
		require.Equal(t, 1999, result.Year())
		require.Equal(t, time.January, result.Month())
		require.Equal(t, 1, result.Day())
	})

	t.Run("invalid format - too short", func(t *testing.T) {
		_, err := ParseDateTime("25031")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid date format")
	})

	t.Run("invalid format - too long", func(t *testing.T) {
		_, err := ParseDateTime("2503155")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid date format")
	})

	t.Run("invalid date values", func(t *testing.T) {
		_, err := ParseDateTime("251399")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error parsing date")
	})

	t.Run("empty string", func(t *testing.T) {
		_, err := ParseDateTime("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid date format")
	})
}

func TestIsEuCitizen(t *testing.T) {
	t.Run("valid EU country uppercase", func(t *testing.T) {
		require.True(t, IsEuCitizen("NLD"))
		require.True(t, IsEuCitizen("DEU"))
		require.True(t, IsEuCitizen("FRA"))
		require.True(t, IsEuCitizen("ESP"))
		require.True(t, IsEuCitizen("ITA"))
	})

	t.Run("valid EU country lowercase", func(t *testing.T) {
		require.True(t, IsEuCitizen("nld"))
		require.True(t, IsEuCitizen("deu"))
		require.True(t, IsEuCitizen("fra"))
	})

	t.Run("valid EU country mixed case", func(t *testing.T) {
		require.True(t, IsEuCitizen("Nld"))
		require.True(t, IsEuCitizen("DeU"))
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

	t.Run("all EU countries", func(t *testing.T) {
		euCountries := []string{
			"AUT", "BEL", "BGR", "HRV", "CYP",
			"CZE", "DNK", "EST", "FIN", "FRA",
			"DEU", "GRC", "HUN", "IRL", "ITA",
			"LVA", "LTU", "LUX", "MLT", "NLD",
			"POL", "PRT", "ROU", "SVK", "SVN",
			"ESP", "SWE",
		}
		for _, country := range euCountries {
			require.True(t, IsEuCitizen(country), "Country %s should be recognized as EU", country)
		}
	})
}

func TestPassiveAuthentication(t *testing.T) {
	t.Run("empty data groups returns error", func(t *testing.T) {
		data := models.PassportValidationRequest{
			DataGroups: map[string]string{},
			EFSOD:      "some_sod_data",
		}
		_, err := PassiveAuthentication(data, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no data groups found")
	})

	t.Run("missing EF_SOD returns error", func(t *testing.T) {
		data := models.PassportValidationRequest{
			DataGroups: map[string]string{
				"DG1": "some_data",
			},
			EFSOD: "",
		}
		_, err := PassiveAuthentication(data, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "EF_SOD is missing")
	})

	t.Run("invalid SOD returns error", func(t *testing.T) {
		data := models.PassportValidationRequest{
			DataGroups: map[string]string{
				"DG1": "some_data",
			},
			EFSOD: "AABBCC",
		}
		_, err := PassiveAuthentication(data, &cms.CombinedCertPool{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create SOD")
	})
}

func TestActiveAuthentication(t *testing.T) {
	t.Run("missing nonce returns false with no error", func(t *testing.T) {
		data := models.PassportValidationRequest{
			Nonce:               "",
			ActiveAuthSignature: "signature",
		}
		doc := document.Document{}
		result, err := ActiveAuthentication(data, doc)
		require.NoError(t, err)
		require.False(t, result)
	})

	t.Run("missing signature returns false with no error", func(t *testing.T) {
		data := models.PassportValidationRequest{
			Nonce:               "nonce",
			ActiveAuthSignature: "",
		}
		doc := document.Document{}
		result, err := ActiveAuthentication(data, doc)
		require.NoError(t, err)
		require.False(t, result)
	})

	t.Run("missing DG15 returns false with no error", func(t *testing.T) {
		data := models.PassportValidationRequest{
			Nonce:               "nonce",
			ActiveAuthSignature: "signature",
		}
		doc := document.Document{}
		result, err := ActiveAuthentication(data, doc)
		require.NoError(t, err)
		require.False(t, result)
	})

	t.Run("all missing returns false with no error", func(t *testing.T) {
		data := models.PassportValidationRequest{
			Nonce:               "",
			ActiveAuthSignature: "",
		}
		doc := document.Document{}
		result, err := ActiveAuthentication(data, doc)
		require.NoError(t, err)
		require.False(t, result)
	})
}
