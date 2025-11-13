package main

import (
	"go-passport-issuer/models"
	"go-passport-issuer/passport"

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

type passportValidatorImpl struct{}

func (passportValidatorImpl) Passive(req models.ValidationRequest, pool *cms.CombinedCertPool) (document.Document, error) {
	return passport.PassiveAuthenticationPassport(req, pool)
}

func (passportValidatorImpl) Active(req models.ValidationRequest, doc document.Document) (bool, error) {
	return passport.ActiveAuthentication(req, doc)
}

type IssuanceRequestConverterImpl struct{}

func (IssuanceRequestConverterImpl) ToPassportData(doc document.Document, active bool) (models.PassportData, error) {
	return passport.ToPassportData(doc, active)
}
