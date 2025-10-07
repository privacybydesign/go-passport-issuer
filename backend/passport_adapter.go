package main

import (
	"go-passport-issuer/models"
	"go-passport-issuer/passport"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
)

// abstract interfaces for easier testing

type PassportValidator interface {
	Passive(models.PassportValidationRequest, *cms.CombinedCertPool) (document.Document, error)
	Active(models.PassportValidationRequest, document.Document) (bool, error)
}

type PassportDataConverter interface {
	ToPassportData(document.Document, bool) (models.PassportData, error)
}

// Production implementations

type passportValidatorImpl struct{}

func (passportValidatorImpl) Passive(req models.PassportValidationRequest, pool *cms.CombinedCertPool) (document.Document, error) {
	return passport.PassiveAuthentication(req, pool)
}

func (passportValidatorImpl) Active(req models.PassportValidationRequest, doc document.Document) (bool, error) {
	return passport.ActiveAuthentication(req, doc)
}

type IssuanceRequestConverterImpl struct{}

func (IssuanceRequestConverterImpl) ToPassportData(doc document.Document, active bool) (models.PassportData, error) {
	return passport.ToPassportData(doc, active)
}
