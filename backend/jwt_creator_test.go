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

	jc, err := NewIrmaJwtCreator("./test-secrets/priv.pem", "passport_issuer", "pbdf-staging.pbdf.passport", 25)
	require.NoError(t, err)

	b, err := os.ReadFile("./test-data/testpasfoto.jpg")
	require.NoError(t, err)
	photoBase64 := base64.StdEncoding.EncodeToString(b)

	var testPassportIssuanceRequest = models.PassportData{
		Photo:                photoBase64,
		DocumentNumber:       "X1234567",
		DocumentType:         "Passport",
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

	createdjwt, err := jc.CreatePassportJwt(testPassportIssuanceRequest)
	if err != nil {
		t.Fatalf("failed to create jwt: %v", err)
	}

	if createdjwt == "" {
		t.Fatal("jwt is empty")
	}
}

func TestDecodeValidateJwt(t *testing.T) {
	// 1) create the jwt
	jc, err := NewIrmaJwtCreator("./test-secrets/priv.pem", "passport_issuer", "pbdf-staging.pbdf.passport", 25)
	require.NoError(t, err)

	b, err := os.ReadFile("./test-data/testpasfoto.jpg")
	require.NoError(t, err)
	photoBase64 := base64.StdEncoding.EncodeToString(b)

	req := models.PassportData{
		Photo:                photoBase64,
		DocumentNumber:       "X1234567",
		DocumentType:         "Passport",
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
			b, err := os.ReadFile("./test-data/testpasfoto.jpg")
			require.NoError(t, err)
			photoBase64 := base64.StdEncoding.EncodeToString(b)

			testPassport := models.PassportData{
				Photo:                photoBase64,
				DocumentNumber:       "TEST123",
				DocumentType:         "Passport",
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
				"dateOfBirth":          testPassport.DateOfBirth.Format("2006-01-02"),
				"yearOfBirth":          testPassport.DateOfBirth.Format("2006"),
				"isEuCitizen":          testPassport.IsEuCitizen,
				"dateOfExpiry":         testPassport.DateOfExpiry.Format("2006-01-02"),
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

func jwtKeyFunc(token *jwt.Token) (interface{}, error) {
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
