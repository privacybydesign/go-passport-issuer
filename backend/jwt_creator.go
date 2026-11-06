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
	CreateResidencePermitJwt(data models.PassportData) (jwt string, err error)
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

// passportDataAttributes returns the attributes for the passport, idcard and
// residencepermit credential types, which all have the same attributes.
func passportDataAttributes(data models.PassportData) map[string]string {
	return map[string]string{
		"photo":                data.Photo,
		"documentNumber":       data.DocumentNumber,
		"documentType":         data.DocumentType,
		"firstName":            data.FirstName,
		"lastName":             data.LastName,
		"nationality":          data.Nationality,
		"dateOfBirth":          data.DateOfBirth.Format(DATE_FORMAT_CYMD),
		"yearOfBirth":          data.DateOfBirth.Format(DATE_FORMAT_YEAR),
		"isEuCitizen":          data.IsEuCitizen,
		"dateOfExpiry":         data.DateOfExpiry.Format(DATE_FORMAT_CYMD),
		"gender":               data.Gender,
		"country":              data.Country,
		"over12":               data.Over12,
		"over16":               data.Over16,
		"over18":               data.Over18,
		"over21":               data.Over21,
		"over65":               data.Over65,
		"activeAuthentication": data.ActiveAuthentication,
	}
}

func (jc *DefaultJwtCreator) CreatePassportJwt(passport models.PassportData) (string, error) {
	if err := isValidPassportDocumentType(passport.DocumentType); err != nil {
		return "", err
	}
	return jc.createJwt(passportDataAttributes(passport))
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
	return jc.createJwt(passportDataAttributes(idCard))
}

// RESIDENCE_PERMIT_DOCUMENT_CODES are the MRZ document codes of issued
// residence permits, the same list vcmrtd recognises them by. Some of them,
// like IR and IT, are also valid ID-card codes.
var RESIDENCE_PERMIT_DOCUMENT_CODES = []string{
	"AD", "AR", "CR", "IB", "IE", "IF", "IK", "IO", "IR", "IT", "IW", "IZ", "RP", "RT",
}

// isValidResidencePermit checks the document code and that the holder is not
// a national of the issuing state: no state issues its own nationals a
// residence permit, so such a card is an ID card.
func isValidResidencePermit(docType, nationality, issuingState string) error {
	if !slices.Contains(RESIDENCE_PERMIT_DOCUMENT_CODES, strings.ReplaceAll(docType, "<", "")) {
		return fmt.Errorf("document with type %s cannot be issued as a residence permit", docType)
	}
	if nationality == issuingState {
		return fmt.Errorf("document issued by %s to one of its own nationals cannot be issued as a residence permit", issuingState)
	}
	return nil
}

func (jc *DefaultJwtCreator) CreateResidencePermitJwt(permit models.PassportData) (string, error) {
	if err := isValidResidencePermit(permit.DocumentType, permit.Nationality, permit.Country); err != nil {
		return "", err
	}
	return jc.createJwt(passportDataAttributes(permit))
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

const EDL_CATEGORY_PREFIX = "category"

// EDL_CATEGORY_CODES are the driving licence categories the drivinglicence
// credential type has attributes for, in the order of the licence card: the
// EU model's rows (Directive 2006/126/EC, Annex I) plus the Dutch T. B1 is
// printed on every EU licence but not issued in the Netherlands (RDW).
var EDL_CATEGORY_CODES = []string{
	"AM", "A1", "A2", "A", "B1", "B", "C1", "C", "D1", "D", "BE", "C1E", "CE", "D1E", "DE", "T",
}

// edlCategoryAttributes returns every category attribute, "" when there is
// no value. An attribute that is not issued is absent from the SD-JWT, and a
// verifier asking for it would find no matching credential. Flags are yes/no
// when the chip yielded categories (a category the parser skipped reads as
// "no") and "" when it yielded none: unknown, not a false "no". Codes
// outside EDL_CATEGORY_CODES are dropped.
func edlCategoryAttributes(categories []models.EDLCategory) map[string]string {
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

	date := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.Format(DATE_FORMAT_CYMD)
	}

	attributes := map[string]string{}
	for _, code := range EDL_CATEGORY_CODES {
		c, ok := held[code]
		flag := ""
		if len(categories) > 0 {
			flag = "no"
			if ok {
				flag = "yes"
			}
		}
		attributes[EDL_CATEGORY_PREFIX+code] = flag
		attributes[EDL_CATEGORY_PREFIX+code+"DateOfIssue"] = date(c.DateOfIssue)
		attributes[EDL_CATEGORY_PREFIX+code+"DateOfExpiry"] = date(c.DateOfExpiry)
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
