package main

import (
	"encoding/json"
	"go-passport-issuer/models"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/privacybydesign/irmago/irma"
	"github.com/stretchr/testify/require"
)

const (
	testDocumentCredential = "pbdf-staging.pbdf.passport"
	testAgeCredential      = "pbdf-staging.pbdf.age"
)

func newAgeJwtCreator(t *testing.T, ageCredential string) *DefaultJwtCreator {
	t.Helper()
	jc, err := NewIrmaJwtCreator("./test-secrets/priv.pem", "passport_issuer", testDocumentCredential, ageCredential, 25)
	require.NoError(t, err)
	return jc
}

func testPassport(t *testing.T) models.PassportData {
	t.Helper()
	return models.PassportData{
		Photo:          loadImage(t),
		DocumentNumber: "X1234567",
		DocumentType:   "P",
		FirstName:      "Alice",
		LastName:       "Johnson",
		DateOfBirth:    time.Date(1990, time.June, 15, 0, 0, 0, 0, time.UTC),
		DateOfExpiry:   time.Date(2030, time.June, 15, 0, 0, 0, 0, time.UTC),
	}
}

func issuanceCredentials(t *testing.T, tokenString string) []*irma.CredentialRequest {
	t.Helper()

	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, jwtKeyFunc)
	require.NoError(t, err)

	var request struct {
		Request irma.IssuanceRequest `json:"request"`
	}
	raw, err := json.Marshal(claims["iprequest"])
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &request))

	return request.Request.Credentials
}

func TestDocumentScopeIssuesOnlyTheDocument(t *testing.T) {
	jc := newAgeJwtCreator(t, testAgeCredential)

	for _, scope := range []models.IssuanceScope{"", models.IssueDocument} {
		request, err := jc.createIssuanceRequest(map[string]string{}, time.Now(), scope)
		require.NoError(t, err)
		require.Len(t, request.Credentials, 1, "scope %q", scope)
		require.Equal(t, testDocumentCredential, request.Credentials[0].CredentialTypeID.String())
	}
}

func TestDocumentAndAgeScopeIssuesBothCredentials(t *testing.T) {
	jc := newAgeJwtCreator(t, testAgeCredential)
	dateOfBirth := time.Date(1990, time.June, 15, 0, 0, 0, 0, time.UTC)

	request, err := jc.createIssuanceRequest(map[string]string{"firstName": "Alice"}, dateOfBirth, models.IssueDocumentAndAge)
	require.NoError(t, err)
	require.Len(t, request.Credentials, 2)

	document, age := request.Credentials[0], request.Credentials[1]
	require.Equal(t, testDocumentCredential, document.CredentialTypeID.String())
	require.Equal(t, "Alice", document.Attributes["firstName"])
	require.Equal(t, testAgeCredential, age.CredentialTypeID.String())
	require.Len(t, age.Attributes, 99)
	require.Equal(t, "Yes", age.Attributes["over18"])
	require.NotContains(t, age.Attributes, "firstName")
	require.Equal(t, document.SdJwtBatchSize, age.SdJwtBatchSize)
}

func TestAgeOnlyScopeIssuesOnlyTheAgeCredential(t *testing.T) {
	jc := newAgeJwtCreator(t, testAgeCredential)

	request, err := jc.createIssuanceRequest(map[string]string{"photo": "secret"}, time.Now(), models.IssueAgeOnly)
	require.NoError(t, err)
	require.Len(t, request.Credentials, 1)
	require.Equal(t, testAgeCredential, request.Credentials[0].CredentialTypeID.String())
	require.NotContains(t, request.Credentials[0].Attributes, "photo")
}

func TestAgeCredentialIsShorterLivedThanTheDocument(t *testing.T) {
	jc := newAgeJwtCreator(t, testAgeCredential)

	request, err := jc.createIssuanceRequest(map[string]string{}, time.Now(), models.IssueDocumentAndAge)
	require.NoError(t, err)

	document, age := request.Credentials[0], request.Credentials[1]
	now := time.Now()
	require.WithinDuration(t, now.AddDate(1, 0, 0), time.Time(*document.Validity), time.Minute)
	require.WithinDuration(t, now.AddDate(0, ageCredentialValidityMonths, 0), time.Time(*age.Validity), time.Minute)
	require.True(t, time.Time(*age.Validity).Before(time.Time(*document.Validity)))
}

func TestAgeScopeNeedsAConfiguredAgeCredential(t *testing.T) {
	jc := newAgeJwtCreator(t, "")

	for _, scope := range []models.IssuanceScope{models.IssueDocumentAndAge, models.IssueAgeOnly} {
		_, err := jc.CreatePassportJwt(testPassport(t), scope)
		require.ErrorIs(t, err, errAgeCredentialNotConfigured, "scope %q", scope)
	}

	_, err := jc.CreatePassportJwt(testPassport(t), models.IssueDocument)
	require.NoError(t, err)
}

func TestSignedJwtCarriesTheRequestedCredentials(t *testing.T) {
	jc := newAgeJwtCreator(t, testAgeCredential)
	passport := testPassport(t)

	both, err := jc.CreatePassportJwt(passport, models.IssueDocumentAndAge)
	require.NoError(t, err)
	credentials := issuanceCredentials(t, both)
	require.Len(t, credentials, 2)
	require.Equal(t, testDocumentCredential, credentials[0].CredentialTypeID.String())
	require.Equal(t, testAgeCredential, credentials[1].CredentialTypeID.String())

	ageOnly, err := jc.CreatePassportJwt(passport, models.IssueAgeOnly)
	require.NoError(t, err)
	credentials = issuanceCredentials(t, ageOnly)
	require.Len(t, credentials, 1)
	require.Equal(t, testAgeCredential, credentials[0].CredentialTypeID.String())
}

func TestAgeScopeAppliesToIdCardAndDrivingLicence(t *testing.T) {
	jc := newAgeJwtCreator(t, testAgeCredential)
	dateOfBirth := time.Date(1990, time.June, 15, 0, 0, 0, 0, time.UTC)

	idCard := testPassport(t)
	idCard.DocumentType = "I"
	idCardJwt, err := jc.CreateIdCardJwt(idCard, models.IssueAgeOnly)
	require.NoError(t, err)
	require.Len(t, issuanceCredentials(t, idCardJwt), 1)

	edlJwt, err := jc.CreateEDLJwt(models.EDLData{DateOfBirth: dateOfBirth}, models.IssueDocumentAndAge)
	require.NoError(t, err)
	require.Len(t, issuanceCredentials(t, edlJwt), 2)
}

func TestAgeOnlyStillChecksTheDocumentType(t *testing.T) {
	jc := newAgeJwtCreator(t, testAgeCredential)

	idCard := testPassport(t)
	idCard.DocumentType = "I"
	_, err := jc.CreatePassportJwt(idCard, models.IssueAgeOnly)
	require.Error(t, err)

	passport := testPassport(t)
	_, err = jc.CreateIdCardJwt(passport, models.IssueAgeOnly)
	require.Error(t, err)
}
