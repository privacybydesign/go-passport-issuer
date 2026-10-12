package main

import (
	"crypto/rsa"
	"fmt"
	"go-passport-issuer/models"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/privacybydesign/irmago/irma"
)

type JwtCreator interface {
	CreatePassportJwt(passport models.PassportData) (jwt string, err error)
	CreateEDLJwt(edl models.EDLData) (jwt string, err error)
	CreateIdCardJwt(data models.PassportData) (jwt string, err error)
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

func isValidPassportDocumentType(docType string) error {
	if strings.HasPrefix(docType, "P") {
		return nil
	}
	return fmt.Errorf("document with type %s cannot be issued as a passport", docType)
}

func (jc *DefaultJwtCreator) CreatePassportJwt(passport models.PassportData) (string, error) {
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

	return jc.createJwt(attributes)
}

func isValidIdCardDocumentType(docType string) error {
	if !strings.HasPrefix(docType, "I") {
		return fmt.Errorf("document with type %s cannot be issued as an ID-card", docType)
	}
	return nil
}

func (jc *DefaultJwtCreator) CreateIdCardJwt(idCard models.PassportData) (string, error) {
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
	maps.Copy(attributes, edlCategoryAttributes(edl.Categories))

	return jc.createJwt(attributes)
}

// EDL_CATEGORY_CODES are the driving licence categories the drivinglicence
// credential type has attributes for, in the order of the licence card: the
// EU model's rows (Directive 2006/126/EC, Annex I) plus the Dutch T. B1 is
// printed on every EU licence but not issued in the Netherlands (RDW).
var EDL_CATEGORY_CODES = []string{
	"AM", "A1", "A2", "A", "B1", "B", "C1", "C", "D1", "D", "BE", "C1E", "CE", "D1E", "DE", "T",
}

const EDL_CATEGORY_PREFIX = "category"

// edlCategoryAttributes returns the category attributes for a driving licence.
// The held flags are all-or-nothing: when the chip yielded no categories none
// are issued, otherwise every category gets categoryX = yes/no, plus its dates
// when held. A category the parser had to skip is therefore issued as "no".
// Codes outside EDL_CATEGORY_CODES are dropped.
func edlCategoryAttributes(categories []models.EDLCategory) map[string]string {
	attributes := map[string]string{}
	if len(categories) == 0 {
		return attributes
	}

	held := map[string]models.EDLCategory{}
	for _, c := range categories {
		code := strings.ToUpper(strings.TrimSpace(c.Code))
		if !slices.Contains(EDL_CATEGORY_CODES, code) {
			slog.Warn("dropping unknown driving licence category", "category", c.Code)
			continue
		}
		if _, dup := held[code]; !dup {
			held[code] = c
		}
	}

	for _, code := range EDL_CATEGORY_CODES {
		c, ok := held[code]
		if !ok {
			attributes[EDL_CATEGORY_PREFIX+code] = "no"
			continue
		}
		attributes[EDL_CATEGORY_PREFIX+code] = "yes"
		if !c.DateOfIssue.IsZero() {
			attributes[EDL_CATEGORY_PREFIX+code+"DateOfIssue"] = c.DateOfIssue.Format(DATE_FORMAT_CYMD)
		}
		if !c.DateOfExpiry.IsZero() {
			attributes[EDL_CATEGORY_PREFIX+code+"DateOfExpiry"] = c.DateOfExpiry.Format(DATE_FORMAT_CYMD)
		}
	}

	return attributes
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
