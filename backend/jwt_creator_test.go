package main

import (
	"encoding/base64"
	"fmt"
	"go-passport-issuer/models"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/require"
)

func TestCreatingJwt(t *testing.T) {
	testPassportIssuanceRequest := models.PassportData{
		Photo:                loadImage(t),
		DocumentNumber:       "X1234567",
		DocumentType:         "P",
		FirstName:            "Alice",
		LastName:             "Johnson",
		Nationality:          "NLD",
		IsEuCitizen:          "true",
		DateOfBirth:          time.Date(1990, time.June, 15, 0, 0, 0, 0, time.UTC),
		YearOfBirth:          "1990",
		DateOfExpiry:         time.Date(2030, time.June, 15, 0, 0, 0, 0, time.UTC),
		Gender:               "F",
		Country:              "Netherlands",
		Over12:               "true",
		Over16:               "true",
		Over18:               "true",
		Over21:               "true",
		Over65:               "false",
		ActiveAuthentication: "true",
	}
	requireValidPassport(t, testPassportIssuanceRequest)
}

func TestIdCardWithDocType_I_IsValid(t *testing.T) {
	testPassportIssuanceRequest := models.PassportData{
		Photo:                loadImage(t),
		DocumentNumber:       "X1234567",
		DocumentType:         "I",
		FirstName:            "Alice",
		LastName:             "Johnson",
		Nationality:          "NLD",
		IsEuCitizen:          "true",
		DateOfBirth:          time.Date(1990, time.June, 15, 0, 0, 0, 0, time.UTC),
		YearOfBirth:          "1990",
		DateOfExpiry:         time.Date(2030, time.June, 15, 0, 0, 0, 0, time.UTC),
		Gender:               "F",
		Country:              "Netherlands",
		Over12:               "true",
		Over16:               "true",
		Over18:               "true",
		Over21:               "true",
		Over65:               "false",
		ActiveAuthentication: "true",
	}
	requireValidIdCard(t, testPassportIssuanceRequest)
}

func TestPassportWithDocType_PP_IsValid(t *testing.T) {
	testPassportIssuanceRequest := models.PassportData{
		Photo:                loadImage(t),
		DocumentNumber:       "X1234567",
		DocumentType:         "PP",
		FirstName:            "Alice",
		LastName:             "Johnson",
		Nationality:          "NLD",
		IsEuCitizen:          "true",
		DateOfBirth:          time.Date(1990, time.June, 15, 0, 0, 0, 0, time.UTC),
		YearOfBirth:          "1990",
		DateOfExpiry:         time.Date(2030, time.June, 15, 0, 0, 0, 0, time.UTC),
		Gender:               "F",
		Country:              "Netherlands",
		Over12:               "true",
		Over16:               "true",
		Over18:               "true",
		Over21:               "true",
		Over65:               "false",
		ActiveAuthentication: "true",
	}
	requireValidPassport(t, testPassportIssuanceRequest)
}

func TestIdCardWithDocType_IT_IsValid(t *testing.T) {
	testPassportIssuanceRequest := models.PassportData{
		Photo:                loadImage(t),
		DocumentNumber:       "X1234567",
		DocumentType:         "IT",
		FirstName:            "Alice",
		LastName:             "Johnson",
		Nationality:          "NLD",
		IsEuCitizen:          "true",
		DateOfBirth:          time.Date(1990, time.June, 15, 0, 0, 0, 0, time.UTC),
		YearOfBirth:          "1990",
		DateOfExpiry:         time.Date(2030, time.June, 15, 0, 0, 0, 0, time.UTC),
		Gender:               "F",
		Country:              "Netherlands",
		Over12:               "true",
		Over16:               "true",
		Over18:               "true",
		Over21:               "true",
		Over65:               "false",
		ActiveAuthentication: "true",
	}
	requireValidIdCard(t, testPassportIssuanceRequest)
}

func TestPassportDocumentTypeIsRefusedAsIdCard(t *testing.T) {
	testPassportIssuanceRequest := models.PassportData{
		Photo:                loadImage(t),
		DocumentNumber:       "X1234567",
		DocumentType:         "P",
		FirstName:            "Alice",
		LastName:             "Johnson",
		Nationality:          "NLD",
		IsEuCitizen:          "true",
		DateOfBirth:          time.Date(1990, time.June, 15, 0, 0, 0, 0, time.UTC),
		YearOfBirth:          "1990",
		DateOfExpiry:         time.Date(2030, time.June, 15, 0, 0, 0, 0, time.UTC),
		Gender:               "F",
		Country:              "Netherlands",
		Over12:               "true",
		Over16:               "true",
		Over18:               "true",
		Over21:               "true",
		Over65:               "false",
		ActiveAuthentication: "true",
	}
	requireInvalidIdCard(t, testPassportIssuanceRequest)
}

func TestIdCardDocumentTypeIsRefusedAsPassport(t *testing.T) {
	testPassportIssuanceRequest := models.PassportData{
		Photo:                loadImage(t),
		DocumentNumber:       "X1234567",
		DocumentType:         "I",
		FirstName:            "Alice",
		LastName:             "Johnson",
		Nationality:          "NLD",
		IsEuCitizen:          "true",
		DateOfBirth:          time.Date(1990, time.June, 15, 0, 0, 0, 0, time.UTC),
		YearOfBirth:          "1990",
		DateOfExpiry:         time.Date(2030, time.June, 15, 0, 0, 0, 0, time.UTC),
		Gender:               "F",
		Country:              "Netherlands",
		Over12:               "true",
		Over16:               "true",
		Over18:               "true",
		Over21:               "true",
		Over65:               "false",
		ActiveAuthentication: "true",
	}
	requireInvalidPassport(t, testPassportIssuanceRequest)
}

func TestDecodeValidateJwt(t *testing.T) {
	// 1) create the jwt
	jc, err := NewIrmaJwtCreator("./test-secrets/priv.pem", "passport_issuer", "pbdf-staging.pbdf.passport", 25)
	require.NoError(t, err)

	req := models.PassportData{
		Photo:                loadImage(t),
		DocumentNumber:       "X1234567",
		DocumentType:         "P",
		FirstName:            "Alice",
		LastName:             "Johnson",
		Nationality:          "NLD",
		IsEuCitizen:          "true",
		DateOfBirth:          time.Date(1990, time.June, 15, 0, 0, 0, 0, time.UTC),
		YearOfBirth:          "1990",
		DateOfExpiry:         time.Date(2030, time.June, 15, 0, 0, 0, 0, time.UTC),
		Gender:               "F",
		Country:              "Netherlands",
		Over12:               "true",
		Over16:               "true",
		Over18:               "true",
		Over21:               "true",
		Over65:               "false",
		ActiveAuthentication: "true",
	}

	tokenString, err := jc.CreatePassportJwt(req)
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)

	// 2) check if valid + 3) verify signature using pub key
	require.NoError(t, err)
	require.NoError(t, err)

	parsedJWT, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, jwtKeyFunc)

	require.NoError(t, err)
	require.NotNil(t, parsedJWT)
	require.True(t, parsedJWT.Valid)

	// Verify document number claim if present
	claims, ok := parsedJWT.Claims.(jwt.MapClaims)
	if ok {
		if docnr, ok := claims["document_number"].(string); ok {
			require.Equal(t, "X1234567", docnr)
		}
	}
	require.Equal(t, true, ok)
}

func TestBatchSizeConfiguration(t *testing.T) {
	testCases := []struct {
		name      string
		batchSize uint
	}{
		{
			name:      "batch size 10",
			batchSize: 10,
		},
		{
			name:      "batch size 25",
			batchSize: 25,
		},
		{
			name:      "batch size 50",
			batchSize: 50,
		},
		{
			name:      "batch size 1",
			batchSize: 1,
		},
		{
			name:      "batch size 100",
			batchSize: 100,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create JWT creator with specific batch size
			jc, err := NewIrmaJwtCreator(
				"./test-secrets/priv.pem",
				"passport_issuer",
				"pbdf-staging.pbdf.passport",
				tc.batchSize,
			)
			require.NoError(t, err)
			require.NotNil(t, jc)

			// Verify the batch size is stored correctly
			require.Equal(t, tc.batchSize, jc.sdJwtBatchSize,
				"JWT creator should store the configured batch size")

			// Create a test passport
			testPassport := models.PassportData{
				Photo:                loadImage(t),
				DocumentNumber:       "TEST123",
				DocumentType:         "P",
				FirstName:            "Test",
				LastName:             "User",
				Nationality:          "NLD",
				IsEuCitizen:          "true",
				DateOfBirth:          time.Date(1990, time.January, 1, 0, 0, 0, 0, time.UTC),
				YearOfBirth:          "1990",
				DateOfExpiry:         time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC),
				Gender:               "M",
				Country:              "Netherlands",
				Over12:               "true",
				Over16:               "true",
				Over18:               "true",
				Over21:               "true",
				Over65:               "false",
				ActiveAuthentication: "true",
			}
			passportAttributes := map[string]string{
				"photo":                testPassport.Photo,
				"documentNumber":       testPassport.DocumentNumber,
				"documentType":         testPassport.DocumentType,
				"firstName":            testPassport.FirstName,
				"lastName":             testPassport.LastName,
				"nationality":          testPassport.Nationality,
				"dateOfBirth":          testPassport.DateOfBirth.Format(DATE_FORMAT_CYMD),
				"yearOfBirth":          testPassport.DateOfBirth.Format(DATE_FORMAT_YEAR),
				"isEuCitizen":          testPassport.IsEuCitizen,
				"dateOfExpiry":         testPassport.DateOfExpiry.Format(DATE_FORMAT_CYMD),
				"gender":               testPassport.Gender,
				"country":              testPassport.Country,
				"over12":               testPassport.Over12,
				"over16":               testPassport.Over16,
				"over18":               testPassport.Over18,
				"over21":               testPassport.Over21,
				"over65":               testPassport.Over65,
				"activeAuthentication": testPassport.ActiveAuthentication,
			}

			// Test that the issuanceRequest has the correct batch size
			issuanceReq := jc.createIssuanceRequest(passportAttributes)
			require.NotNil(t, issuanceReq)
			require.Len(t, issuanceReq.Credentials, 1, "Should have exactly one credential request")
			require.Equal(t, tc.batchSize, issuanceReq.Credentials[0].SdJwtBatchSize,
				"IssuanceRequest credential should have the configured batch size")

			// Create JWT and verify it can be created successfully
			jwtString, err := jc.CreatePassportJwt(testPassport)
			require.NoError(t, err)
			require.NotEmpty(t, jwtString)

			// Verify the JWT can be parsed
			parsedJWT, err := jwt.ParseWithClaims(jwtString, jwt.MapClaims{}, jwtKeyFunc)
			require.NoError(t, err)
			require.NotNil(t, parsedJWT)
			require.True(t, parsedJWT.Valid)
		})
	}
}

func jwtKeyFunc(token *jwt.Token) (any, error) {
	pubBytes, err := os.ReadFile("./test-secrets/pub.pem")
	if err != nil {
		return nil, err
	}
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(pubBytes)
	if err != nil {
		return nil, err
	}

	// Ensure the signing method is RS256
	if token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
		return nil, fmt.Errorf("unexpected signing method: %s", token.Header["alg"])
	}
	return pubKey, nil
}

func TestNewIrmaJwtCreator_ErrorCases(t *testing.T) {
	t.Run("file not found", func(t *testing.T) {
		_, err := NewIrmaJwtCreator("./nonexistent.pem", "issuer", "credential", 25)
		require.Error(t, err)
	})

	t.Run("invalid PEM format", func(t *testing.T) {
		// Create a temporary invalid PEM file
		tmpFile, err := os.CreateTemp("", "invalid-*.pem")
		require.NoError(t, err)
		defer func() { _ = os.Remove(tmpFile.Name()) }()

		_, err = tmpFile.Write([]byte("this is not a valid PEM file"))
		require.NoError(t, err)
		require.NoError(t, tmpFile.Close())

		_, err = NewIrmaJwtCreator(tmpFile.Name(), "issuer", "credential", 25)
		require.Error(t, err)
	})
}

func loadImage(t *testing.T) string {
	b, err := os.ReadFile("./test-data/testpasfoto.jpg")
	require.NoError(t, err)
	photoBase64 := base64.StdEncoding.EncodeToString(b)
	return photoBase64
}

func requireValidIdCard(t *testing.T, data models.PassportData) {
	jc, err := NewIrmaJwtCreator("./test-secrets/priv.pem", "passport_issuer", "pbdf-staging.pbdf.idcard", 25)
	require.NoError(t, err)
	jwt, err := jc.CreateIdCardJwt(data)
	require.NoError(t, err)
	require.NotEmpty(t, jwt)
}

func requireInvalidIdCard(t *testing.T, data models.PassportData) {
	jc, err := NewIrmaJwtCreator("./test-secrets/priv.pem", "passport_issuer", "pbdf-staging.pbdf.idcard", 25)
	require.NoError(t, err)
	_, err = jc.CreateIdCardJwt(data)
	require.Error(t, err)
}

func requireValidPassport(t *testing.T, data models.PassportData) {
	jc, err := NewIrmaJwtCreator("./test-secrets/priv.pem", "passport_issuer", "pbdf-staging.pbdf.passport", 25)
	require.NoError(t, err)
	jwt, err := jc.CreatePassportJwt(data)
	require.NoError(t, err)
	require.NotEmpty(t, jwt)
}

func requireInvalidPassport(t *testing.T, data models.PassportData) {
	jc, err := NewIrmaJwtCreator("./test-secrets/priv.pem", "passport_issuer", "pbdf-staging.pbdf.passport", 25)
	require.NoError(t, err)
	_, err = jc.CreatePassportJwt(data)
	require.Error(t, err)
}

func TestEdlCategoryAttributes(t *testing.T) {
	issued := time.Date(2015, time.March, 1, 0, 0, 0, 0, time.UTC)
	expires := time.Date(2030, time.March, 1, 0, 0, 0, 0, time.UTC)
	all := 3 * len(EDL_CATEGORY_CODES)

	t.Run("no categories on the chip: every attribute, all empty", func(t *testing.T) {
		attrs := edlCategoryAttributes(nil)
		require.Len(t, attrs, all)
		for k, v := range attrs {
			require.Empty(t, v, k)
		}
	})

	t.Run("held categories get yes and dates, the rest no with empty dates", func(t *testing.T) {
		attrs := edlCategoryAttributes([]models.EDLCategory{
			{Code: "B", DateOfIssue: issued, DateOfExpiry: expires},
			{Code: "AM", DateOfExpiry: expires},
		})

		require.Len(t, attrs, all)
		require.Equal(t, "yes", attrs["categoryB"])
		require.Equal(t, "2015-03-01", attrs["categoryBDateOfIssue"])
		require.Equal(t, "2030-03-01", attrs["categoryBDateOfExpiry"])
		require.Equal(t, "yes", attrs["categoryAM"])
		require.Equal(t, "", attrs["categoryAMDateOfIssue"], "empty issue date is issued empty")
		require.Equal(t, "2030-03-01", attrs["categoryAMDateOfExpiry"])
		for _, code := range EDL_CATEGORY_CODES {
			if code == "B" || code == "AM" {
				continue
			}
			require.Equal(t, "no", attrs["category"+code])
			require.Contains(t, attrs, "category"+code+"DateOfIssue")
			require.Equal(t, "", attrs["category"+code+"DateOfIssue"])
			require.Contains(t, attrs, "category"+code+"DateOfExpiry")
			require.Equal(t, "", attrs["category"+code+"DateOfExpiry"])
		}
	})

	t.Run("unknown codes are dropped", func(t *testing.T) {
		attrs := edlCategoryAttributes([]models.EDLCategory{
			{Code: "X9", DateOfIssue: issued, DateOfExpiry: expires},
			{Code: "C", DateOfIssue: issued, DateOfExpiry: expires},
		})
		require.NotContains(t, attrs, "categoryX9")
		require.Equal(t, "yes", attrs["categoryC"])
		require.Len(t, attrs, all)
	})

	t.Run("only unknown codes still issues every flag as no", func(t *testing.T) {
		attrs := edlCategoryAttributes([]models.EDLCategory{{Code: "X9", DateOfExpiry: expires}})
		require.Len(t, attrs, all)
		for _, code := range EDL_CATEGORY_CODES {
			require.Equal(t, "no", attrs["category"+code])
		}
	})

	t.Run("B1 is a normal category", func(t *testing.T) {
		attrs := edlCategoryAttributes([]models.EDLCategory{{Code: "B1", DateOfExpiry: expires}})
		require.Equal(t, "yes", attrs["categoryB1"])
		require.Equal(t, "2030-03-01", attrs["categoryB1DateOfExpiry"])
		require.Equal(t, "no", attrs["categoryB"])
	})

	t.Run("codes are normalised and the first duplicate wins", func(t *testing.T) {
		later := time.Date(2031, time.January, 1, 0, 0, 0, 0, time.UTC)
		attrs := edlCategoryAttributes([]models.EDLCategory{
			{Code: " be ", DateOfExpiry: expires},
			{Code: "BE", DateOfExpiry: later},
		})
		require.Equal(t, "yes", attrs["categoryBE"])
		require.Equal(t, "2030-03-01", attrs["categoryBEDateOfExpiry"])
	})
}

func TestCreateEDLJwtIncludesCategories(t *testing.T) {
	jc, err := NewIrmaJwtCreator("./test-secrets/priv.pem", "passport_issuer", "pbdf-staging.pbdf.drivinglicence", 25)
	require.NoError(t, err)

	tokenString, err := jc.CreateEDLJwt(models.EDLData{
		DocumentNumber: "D1234567",
		DateOfBirth:    time.Date(1990, time.June, 15, 0, 0, 0, 0, time.UTC),
		DateOfExpiry:   time.Date(2030, time.June, 15, 0, 0, 0, 0, time.UTC),
		Categories: []models.EDLCategory{{
			Code:         "B",
			DateOfIssue:  time.Date(2015, time.March, 1, 0, 0, 0, 0, time.UTC),
			DateOfExpiry: time.Date(2030, time.March, 1, 0, 0, 0, 0, time.UTC),
		}},
	})
	require.NoError(t, err)

	parsed, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, jwtKeyFunc)
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)
	credentials := claims["iprequest"].(map[string]any)["request"].(map[string]any)["credentials"].([]any)
	attrs := credentials[0].(map[string]any)["attributes"].(map[string]any)

	require.Equal(t, "D1234567", attrs["documentNumber"])
	require.Equal(t, "yes", attrs["categoryB"])
	require.Equal(t, "2015-03-01", attrs["categoryBDateOfIssue"])
	require.Equal(t, "2030-03-01", attrs["categoryBDateOfExpiry"])
	require.Equal(t, "no", attrs["categoryC"])
	require.Equal(t, "", attrs["categoryCDateOfExpiry"], "issued, empty")
}
