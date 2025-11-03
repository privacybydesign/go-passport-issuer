package main

import (
	"encoding/base64"
	"fmt"
	"go-passport-issuer/models"
	"os"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
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

	jwt, err := jc.CreateJwt(testPassportIssuanceRequest)
	if err != nil {
		t.Fatalf("failed to create jwt: %v", err)
	}

	if jwt == "" {
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

	tokenString, err := jc.CreateJwt(req)
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
