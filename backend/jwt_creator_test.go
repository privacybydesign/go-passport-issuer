package main

import (
	"encoding/base64"
	"go-passport-issuer/models"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCreatingJwt(t *testing.T) {

	jc, err := NewIrmaJwtCreator("./test-secrets/priv.pem", "passport_issuer", "pbdf-staging.pbdf.passport")
	require.NoError(t, err)

	b, err := os.ReadFile("./test-data/testpasfoto.jpg")
	require.NoError(t, err)
	photoBase64 := base64.StdEncoding.EncodeToString(b)

	var testPassportIssuanceRequest = models.PassportIssuanceRequest{
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
