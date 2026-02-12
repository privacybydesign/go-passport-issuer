package main

import (
	"go-passport-issuer/document/edl"
	"go-passport-issuer/document/passport"
	"go-passport-issuer/models"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
)

// abstract interfaces for easier testing

type DocumentValidator interface {
	PassivePassport(models.ValidationRequest, *cms.CombinedCertPool, string) (document.Document, error)
	ActivePassport(models.ValidationRequest, document.Document, string) (bool, error)
	PassiveEDL(models.ValidationRequest, *cms.CertPool) error
	ActiveEDL(models.ValidationRequest) (bool, error)
}

type DrivingLicenceParser interface {
	ParseEDLDocument(dataGroups map[string]string, sodHex string) (*edl.DrivingLicenceDocument, error)
}

type DrivingLicenceParserImpl struct{}

func (DrivingLicenceParserImpl) ParseEDLDocument(dataGroups map[string]string, sodHex string) (*edl.DrivingLicenceDocument, error) {
	return edl.ParseEDLDocument(dataGroups, sodHex)
}

type DocumentDataConverter interface {
	ToPassportData(document.Document, bool) (models.PassportData, error)
	ToDrivingLicenceData(edl.DrivingLicenceDocument, bool) (models.EDLData, error)
}

// Production implementations

type DocumentValidatorImpl struct{}

func (DocumentValidatorImpl) PassivePassport(req models.ValidationRequest, pool *cms.CombinedCertPool, documentType string) (document.Document, error) {
	return passport.PassiveAuthenticationPassport(req, pool, documentType)
}

func (DocumentValidatorImpl) ActivePassport(req models.ValidationRequest, doc document.Document, documentType string) (bool, error) {
	return passport.ActiveAuthentication(req, doc, documentType)
}

func (DocumentValidatorImpl) PassiveEDL(req models.ValidationRequest, pool *cms.CertPool) error {
	return edl.PassiveAuthenticationEDL(req, pool)
}
func (DocumentValidatorImpl) ActiveEDL(req models.ValidationRequest) (bool, error) {
	return edl.ActiveAuthenticationEDL(req)
}

type IssuanceRequestConverterImpl struct{}

func (IssuanceRequestConverterImpl) ToPassportData(doc document.Document, active bool) (models.PassportData, error) {
	return passport.ToPassportData(doc, active)
}

func (IssuanceRequestConverterImpl) ToDrivingLicenceData(doc edl.DrivingLicenceDocument, active bool) (models.EDLData, error) {
	return edl.ToDrivingLicenceData(doc, active)
}
