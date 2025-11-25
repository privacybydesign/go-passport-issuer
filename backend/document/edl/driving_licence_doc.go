package edl

import (
	"go-passport-issuer/images"
	"time"

	"github.com/gmrtd/gmrtd/document"
)

// EDLDocument represents a parsed European Driving License
type EDLDocument struct {
	Sod  *document.SOD
	Dg1  *EDLDG1
	Dg6  *EDLDG6
	Dg13 *EDLDG13
}

type DrivingLicenseCategory struct {
	Category     string
	DateOfIssue  time.Time
	DateOfExpiry time.Time
}

type EDLDG1 struct {
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

type EDLDG5 struct {
	RawData   []byte
	Signature images.ImageContainer
}

type EDLDG6 struct {
	RawData []byte
	images.ImageContainer
}

type EDLDG13 struct {
	RawData              []byte
	SubjectPublicKeyInfo []byte
}
