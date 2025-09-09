package main

import (
	"crypto/rsa"
	"go-passport-issuer/models"
	"os"

	"github.com/golang-jwt/jwt/v4"
	irma "github.com/privacybydesign/irmago"
)

type JwtCreator interface {
	CreateJwt(passport models.PassportIssuanceRequest) (jwt string, err error)
}

func NewIrmaJwtCreator(privateKeyPath string,
	issuerId string,
	crediential string,
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
		issuerId:   issuerId,
		privateKey: privateKey,
		credential: crediential,
	}, nil
}

type DefaultJwtCreator struct {
	privateKey *rsa.PrivateKey
	issuerId   string
	credential string
}

func (jc *DefaultJwtCreator) CreateJwt(passport models.PassportIssuanceRequest) (string, error) {
	issuanceRequest := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier(jc.credential),
			Attributes: map[string]string{
				"photo":                passport.Photo,
				"documentNumber":       passport.DocumentNumber,
				"documentType":         passport.DocumentType,
				"firstName":            passport.FirstName,
				"lastName":             passport.LastName,
				"nationality":          passport.Nationality,
				"dateOfBirth":          passport.DateOfBirth.Format("2006-01-02"),
				"yearOfBirth":          passport.DateOfBirth.Format("2006"),
				"isEUCitizen":          passport.IsEUCitizen,
				"dateOfExpiry":         passport.DateOfExpiry.Format("2006-01-02"),
				"gender":               passport.Gender,
				"country":              passport.Country,
				"over12":               passport.Over12,
				"over16":               passport.Over16,
				"over18":               passport.Over18,
				"over21":               passport.Over21,
				"over65":               passport.Over65,
				"activeAuthentication": passport.ActiveAuthentication,
			},
			SdJwtBatchSize: irma.DefaultSdJwtIssueAmount,
		},
	})

	return irma.SignSessionRequest(
		issuanceRequest,
		jwt.GetSigningMethod(jwt.SigningMethodRS256.Alg()),
		jc.privateKey,
		jc.issuerId,
	)
}
