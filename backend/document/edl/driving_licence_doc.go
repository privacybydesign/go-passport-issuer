package edl

import (
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
	HolderOtherName    string
	DateOfBirth        time.Time
	PlaceOfBirth       string
	DateOfIssue        time.Time
	DateOfExpiry       time.Time
	IssuingAuthority   string
	DocumentNumber     string
	Categories         []DrivingLicenseCategory
}

type EDLDG6 struct {
	RawData   []byte
	ImageData []byte
	ImageType string
}

type EDLDG13 struct {
	RawData              []byte
	SubjectPublicKeyInfo []byte
}
