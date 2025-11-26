package main

import (
	"crypto/rsa"
	"go-passport-issuer/models"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	irma "github.com/privacybydesign/irmago"
)

type JwtCreator interface {
	CreatePassportJwt(passport models.PassportData) (jwt string, err error)
	CreateEDLJwt(edl models.EDLData) (jwt string, err error)
}

func NewIrmaJwtCreator(privateKeyPath string,
	issuerId string,
	credential string,
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
		sdJwtBatchSize: sdJwtBatchSize,
	}, nil
}

type DefaultJwtCreator struct {
	privateKey     *rsa.PrivateKey
	issuerId       string
	credential     string
	sdJwtBatchSize uint
}

func (jc *DefaultJwtCreator) createJwt(attributes map[string]string) (string, error) {
	issuanceRequest := jc.createIssuanceRequest(attributes)

	return irma.SignSessionRequest(
		issuanceRequest,
		jwt.GetSigningMethod(jwt.SigningMethodRS256.Alg()),
		jc.privateKey,
		jc.issuerId,
	)
}

const DATE_FORMAT_CYMD = "2006-01-02"
const DATE_FORMAT_YEAR = "2006"

func (jc *DefaultJwtCreator) CreatePassportJwt(passport models.PassportData) (string, error) {
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

	return jc.createJwt(attributes)
}

func (jc *DefaultJwtCreator) CreateEDLJwt(edl models.EDLData) (string, error) {
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

	return jc.createJwt(attributes)
}

// createIssuanceRequest creates an IRMA issuance request with the passport data
// This is a separate method to allow for easier testing
func (jc *DefaultJwtCreator) createIssuanceRequest(attributes map[string]string) *irma.IssuanceRequest {
	validity := irma.Timestamp(time.Unix(time.Now().AddDate(1, 0, 0).Unix(), 0)) // 1 year from now

	return irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier(jc.credential),
			Attributes:       attributes,
			SdJwtBatchSize:   jc.sdJwtBatchSize,
			Validity:         &validity,
		},
	})
}
