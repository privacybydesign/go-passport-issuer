package main

import (
	"go-passport-issuer/document/edl"
	"go-passport-issuer/document/passport"
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
	return passport.PassiveAuthenticationPassport(req, pool)
}

func (PassportValidatorImpl) Active(req models.ValidationRequest, doc document.Document) (bool, error) {
	return passport.ActiveAuthentication(req, doc)
}

type DrivingLicenceValidator interface {
	Passive(models.ValidationRequest, *cms.CertPool) error
	Active(models.ValidationRequest) (bool, error)
}

func (DrivingLicenceValidatorImpl) Passive(req models.ValidationRequest, pool *cms.CertPool) error {
	return edl.PassiveAuthenticationEDL(req, pool)
}
func (DrivingLicenceValidatorImpl) Active(req models.ValidationRequest) (bool, error) {
	return edl.ActiveAuthenticationEDL(req)
}

type DrivingLicenceValidatorImpl struct{}

type IssuanceRequestConverterImpl struct{}

func (IssuanceRequestConverterImpl) ToPassportData(doc document.Document, active bool) (models.PassportData, error) {
	return passport.ToPassportData(doc, active)
}
