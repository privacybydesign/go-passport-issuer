package main

import (
	mrtdDoc "go-passport-issuer/document"
	"go-passport-issuer/models"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
)

// abstract interfaces for easier testing

type PassportValidator interface {
	Passive(models.ValidationRequest, *cms.CombinedCertPool) (document.Document, error)
	Active(models.ValidationRequest, document.Document) (bool, error)
}

type PassportDataConverter interface {
	ToPassportData(document.Document, bool) (models.PassportData, error)
}

// Production implementations

type PassportValidatorImpl struct{}

func (PassportValidatorImpl) Passive(req models.ValidationRequest, pool *cms.CombinedCertPool) (document.Document, error) {
	return mrtdDoc.PassiveAuthenticationPassport(req, pool)
}

func (PassportValidatorImpl) Active(req models.ValidationRequest, doc document.Document) (bool, error) {
	return mrtdDoc.ActiveAuthentication(req, doc)
}

type DrivingLicenceValidator interface {
	Passive(models.ValidationRequest, *cms.CertPool) error
}

func (DrivingLicenceValidatorImpl) Passive(req models.ValidationRequest, pool *cms.CertPool) error {
	return mrtdDoc.PassiveAuthenticationEDL(req, pool)
}

type DrivingLicenceValidatorImpl struct{}

type IssuanceRequestConverterImpl struct{}

func (IssuanceRequestConverterImpl) ToPassportData(doc document.Document, active bool) (models.PassportData, error) {
	return mrtdDoc.ToPassportData(doc, active)
}
