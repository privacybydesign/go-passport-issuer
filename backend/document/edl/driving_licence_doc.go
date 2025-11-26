package edl

import (
	"go-passport-issuer/images"
	"time"

	"github.com/gmrtd/gmrtd/document"
)

// DrivingLicenceDocument represents a parsed European Driving License
type DrivingLicenceDocument struct {
	Sod  *document.SOD
	Dg1  *DG1
	Dg6  *DG6
	Dg13 *DG13
}

type DrivingLicenseCategory struct {
	Category     string
	DateOfIssue  time.Time
	DateOfExpiry time.Time
}

type DG1 struct {
	RawData            []byte
	IssuingMemberState string
	HolderSurname      string
	HolderFirstName    string
	DateOfBirth        time.Time
	PlaceOfBirth       string
	DateOfIssue        time.Time
	DateOfExpiry       time.Time
	IssuingAuthority   string
	DocumentNumber     string
	Categories         []DrivingLicenseCategory
}

type DG5 struct {
	RawData   []byte
	Signature images.ImageContainer
}

type DG6 struct {
	RawData []byte
	images.ImageContainer
}

type DG13 struct {
	RawData              []byte
	SubjectPublicKeyInfo []byte
}
