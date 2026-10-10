package main

import (
	"crypto/rsa"
	"errors"
	"fmt"
	mrtdDoc "go-passport-issuer/document"
	"go-passport-issuer/models"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/privacybydesign/irmago/irma"
)

type JwtCreator interface {
	CreatePassportJwt(passport models.PassportData, scope models.IssuanceScope) (jwt string, err error)
	CreateEDLJwt(edl models.EDLData, scope models.IssuanceScope) (jwt string, err error)
	CreateIdCardJwt(data models.PassportData, scope models.IssuanceScope) (jwt string, err error)
}

var errAgeCredentialNotConfigured = errors.New("age credential is not configured")

func NewIrmaJwtCreator(privateKeyPath string,
	issuerId string,
	credential string,
	ageCredential string,
	sdJwtBatchSize uint,
) (*DefaultJwtCreator, error) {
	keyBytes, err := os.ReadFile(privateKeyPath)

	if err != nil {
		return nil, err
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)

	if err != nil {
		return nil, err
	}

	return &DefaultJwtCreator{
		issuerId:       issuerId,
		privateKey:     privateKey,
		credential:     credential,
		ageCredential:  ageCredential,
		sdJwtBatchSize: sdJwtBatchSize,
	}, nil
}

type DefaultJwtCreator struct {
	privateKey     *rsa.PrivateKey
	issuerId       string
	credential     string
	ageCredential  string
	sdJwtBatchSize uint
}

func (jc *DefaultJwtCreator) createJwt(attributes map[string]string, dateOfBirth time.Time, scope models.IssuanceScope) (string, error) {
	issuanceRequest, err := jc.createIssuanceRequest(attributes, dateOfBirth, scope)
	if err != nil {
		return "", err
	}

	return irma.SignSessionRequest(
		issuanceRequest,
		jwt.GetSigningMethod(jwt.SigningMethodRS256.Alg()),
		jc.privateKey,
		jc.issuerId,
	)
}

const DATE_FORMAT_CYMD = "2006-01-02"
const DATE_FORMAT_YEAR = "2006"

const ageCredentialValidityMonths = 1

func isValidPassportDocumentType(docType string) error {
	if strings.HasPrefix(docType, "P") {
		return nil
	}
	return fmt.Errorf("document with type %s cannot be issued as a passport", docType)
}

func (jc *DefaultJwtCreator) CreatePassportJwt(passport models.PassportData, scope models.IssuanceScope) (string, error) {
	if err := isValidPassportDocumentType(passport.DocumentType); err != nil {
		return "", err
	}
	attributes := map[string]string{
		"photo":                passport.Photo,
		"documentNumber":       passport.DocumentNumber,
		"documentType":         passport.DocumentType,
		"firstName":            passport.FirstName,
		"lastName":             passport.LastName,
		"nationality":          passport.Nationality,
		"dateOfBirth":          passport.DateOfBirth.Format(DATE_FORMAT_CYMD),
		"yearOfBirth":          passport.DateOfBirth.Format(DATE_FORMAT_YEAR),
		"isEuCitizen":          passport.IsEuCitizen,
		"dateOfExpiry":         passport.DateOfExpiry.Format(DATE_FORMAT_CYMD),
		"gender":               passport.Gender,
		"country":              passport.Country,
		"over12":               passport.Over12,
		"over16":               passport.Over16,
		"over18":               passport.Over18,
		"over21":               passport.Over21,
		"over65":               passport.Over65,
		"activeAuthentication": passport.ActiveAuthentication,
	}

	return jc.createJwt(attributes, passport.DateOfBirth, scope)
}

func isValidIdCardDocumentType(docType string) error {
	if !strings.HasPrefix(docType, "I") {
		return fmt.Errorf("document with type %s cannot be issued as an ID-card", docType)
	}
	return nil
}

func (jc *DefaultJwtCreator) CreateIdCardJwt(idCard models.PassportData, scope models.IssuanceScope) (string, error) {
	if err := isValidIdCardDocumentType(idCard.DocumentType); err != nil {
		return "", err
	}

	attributes := map[string]string{
		"photo":                idCard.Photo,
		"documentNumber":       idCard.DocumentNumber,
		"documentType":         idCard.DocumentType,
		"firstName":            idCard.FirstName,
		"lastName":             idCard.LastName,
		"nationality":          idCard.Nationality,
		"dateOfBirth":          idCard.DateOfBirth.Format(DATE_FORMAT_CYMD),
		"yearOfBirth":          idCard.DateOfBirth.Format(DATE_FORMAT_YEAR),
		"isEuCitizen":          idCard.IsEuCitizen,
		"dateOfExpiry":         idCard.DateOfExpiry.Format(DATE_FORMAT_CYMD),
		"gender":               idCard.Gender,
		"country":              idCard.Country,
		"over12":               idCard.Over12,
		"over16":               idCard.Over16,
		"over18":               idCard.Over18,
		"over21":               idCard.Over21,
		"over65":               idCard.Over65,
		"activeAuthentication": idCard.ActiveAuthentication,
	}

	return jc.createJwt(attributes, idCard.DateOfBirth, scope)
}

func (jc *DefaultJwtCreator) CreateEDLJwt(edl models.EDLData, scope models.IssuanceScope) (string, error) {
	attributes := map[string]string{
		"photo":                edl.Photo,
		"documentNumber":       edl.DocumentNumber,
		"firstName":            edl.FirstName,
		"lastName":             edl.LastName,
		"issuingMemberState":   edl.IssuingMemberState,
		"issuingAuthority":     edl.IssuingAuthority,
		"dateOfBirth":          edl.DateOfBirth.Format(DATE_FORMAT_CYMD),
		"yearOfBirth":          edl.DateOfBirth.Format(DATE_FORMAT_YEAR),
		"placeOfBirth":         edl.PlaceOfBirth,
		"dateOfExpiry":         edl.DateOfExpiry.Format(DATE_FORMAT_CYMD),
		"over12":               edl.Over12,
		"over16":               edl.Over16,
		"over18":               edl.Over18,
		"over21":               edl.Over21,
		"over65":               edl.Over65,
		"activeAuthentication": edl.ActiveAuthentication,
	}

	return jc.createJwt(attributes, edl.DateOfBirth, scope)
}

// createIssuanceRequest creates an IRMA issuance request with the credentials
// the scope asks for. This is a separate method to allow for easier testing
func (jc *DefaultJwtCreator) createIssuanceRequest(attributes map[string]string, dateOfBirth time.Time, scope models.IssuanceScope) (*irma.IssuanceRequest, error) {
	var credentials []*irma.CredentialRequest

	if scope.IncludesDocument() {
		validity := irma.Timestamp(time.Unix(time.Now().AddDate(1, 0, 0).Unix(), 0)) // 1 year from now

		credentials = append(credentials, &irma.CredentialRequest{
			CredentialTypeID: irma.NewCredentialTypeIdentifier(jc.credential),
			Attributes:       attributes,
			SdJwtBatchSize:   jc.sdJwtBatchSize,
			Validity:         &validity,
		})
	}

	if scope.IncludesAge() {
		if jc.ageCredential == "" {
			return nil, errAgeCredentialNotConfigured
		}

		// A "no" goes stale as the holder ages. Capping at the next birthday
		// could leave a validity of one day, so use a fixed short validity.
		now := time.Now()
		validity := irma.Timestamp(time.Unix(now.AddDate(0, ageCredentialValidityMonths, 0).Unix(), 0))

		credentials = append(credentials, &irma.CredentialRequest{
			CredentialTypeID: irma.NewCredentialTypeIdentifier(jc.ageCredential),
			Attributes:       mrtdDoc.AgeAttributes(dateOfBirth, now),
			SdJwtBatchSize:   jc.sdJwtBatchSize,
			Validity:         &validity,
		})
	}

	return irma.NewIssuanceRequest(credentials), nil
}
