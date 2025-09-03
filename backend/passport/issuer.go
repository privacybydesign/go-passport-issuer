package passport

import (
	"fmt"
	"go-passport-issuer/images"
	"go-passport-issuer/models"
	"time"

	"github.com/dibranmulder/gmrtd/activeauth"
	"github.com/dibranmulder/gmrtd/cms"
	"github.com/dibranmulder/gmrtd/document"
	"github.com/dibranmulder/gmrtd/passiveauth"
	"github.com/dibranmulder/gmrtd/utils"
)

func PassiveAuthentication(data models.PassportValidationRequest, certPool *cms.CombinedCertPool) (doc document.Document, err error) {
	if len(data.DataGroups) == 0 {
		return document.Document{}, fmt.Errorf("no data groups found in passport data")
	}

	if data.EFSOD == "" {
		return document.Document{}, fmt.Errorf("EF_SOD is missing in passport data")
	}

	var sodFileBytes = utils.HexToBytes(data.EFSOD)
	doc.Mf.Lds1.Sod, err = document.NewSOD(sodFileBytes)
	if err != nil {
		return document.Document{}, fmt.Errorf("failed to create SOD: %w", err)
	}
	for dg := range data.DataGroups {
		dataGroupBytes := utils.HexToBytes(data.DataGroups[dg])

		switch dg {
		case "DG1":
			doc.Mf.Lds1.Dg1, err = document.NewDG1(dataGroupBytes)
		case "DG2":
			doc.Mf.Lds1.Dg2, err = document.NewDG2(dataGroupBytes)
		case "DG7":
			doc.Mf.Lds1.Dg7, err = document.NewDG7(dataGroupBytes)
		case "DG11":
			doc.Mf.Lds1.Dg11, err = document.NewDG11(dataGroupBytes)
		case "DG12":
			doc.Mf.Lds1.Dg12, err = document.NewDG12(dataGroupBytes)
		case "DG13":
			doc.Mf.Lds1.Dg13, err = document.NewDG13(dataGroupBytes)
		case "DG14":
			doc.Mf.Lds1.Dg14, err = document.NewDG14(dataGroupBytes)
		case "DG15":
			doc.Mf.Lds1.Dg15, err = document.NewDG15(dataGroupBytes)
		case "DG16":
			doc.Mf.Lds1.Dg16, err = document.NewDG16(dataGroupBytes)
		default:
			return document.Document{}, fmt.Errorf("unsupported data group: %s", dg)
		}

		if err != nil {
			return document.Document{}, fmt.Errorf("failed to create %s: %w", dg, err)
		}
	}

	err = passiveauth.PassiveAuth(&doc, certPool)
	if err != nil {
		return document.Document{}, fmt.Errorf("unexpected error: %s", err)
	}

	return doc, nil
}

func ActiveAuthentication(data models.PassportValidationRequest, doc document.Document) (bool, error) {
	if data.Nonce == "" || data.ActiveAuthSignature == "" || doc.Mf.Lds1.Dg15 == nil {
		return false, nil
	}

	aaSigBytes := utils.HexToBytes(data.ActiveAuthSignature)
	nonceBytes := utils.HexToBytes(data.Nonce)

	activeauth := activeauth.NewActiveAuth(nil, &doc)
	err := activeauth.ValidateActiveAuthSignature(aaSigBytes, nonceBytes)
	if err != nil {
		return false, fmt.Errorf("failed to validate active authentication signature: %w", err)
	}
	return true, nil
}

func ToPassportIssuanceRequest(doc document.Document, activeAuth bool) (request models.PassportIssuanceRequest, err error) {
	var dob, doe time.Time
	dob, err = ParseDateTime(doc.Mf.Lds1.Dg1.Mrz.DateOfBirth)
	if err != nil {
		return models.PassportIssuanceRequest{}, fmt.Errorf("failed to parse date of birth: %w", err)
	}

	doe, err = ParseDateTime(doc.Mf.Lds1.Dg1.Mrz.DateOfExpiry)
	if err != nil {
		return models.PassportIssuanceRequest{}, fmt.Errorf("failed to parse date of expiry: %w", err)
	}

	efDG2, err := images.NewEfDG2FromBytes(doc.Mf.Lds1.Dg2.RawData)
	if err != nil {
		return models.PassportIssuanceRequest{}, fmt.Errorf("failed to create EfDG2: %w", err)
	}
	pngs, err := efDG2.ConvertToPNG()
	if err != nil {
		return models.PassportIssuanceRequest{}, fmt.Errorf("failed to convert EF DG2 images to PNG: %w", err)
	}

	request = models.PassportIssuanceRequest{
		DocumentNumber:       doc.Mf.Lds1.Dg1.Mrz.DocumentNumber,
		DocumentType:         doc.Mf.Lds1.Dg1.Mrz.DocumentCode,
		FirstName:            doc.Mf.Lds1.Dg1.Mrz.NameOfHolder.Secondary,
		LastName:             doc.Mf.Lds1.Dg1.Mrz.NameOfHolder.Primary,
		Nationality:          doc.Mf.Lds1.Dg1.Mrz.Nationality,
		DateOfBirth:          dob,
		DateOfExpiry:         doe,
		Gender:               doc.Mf.Lds1.Dg1.Mrz.Sex,
		Country:              doc.Mf.Lds1.Dg1.Mrz.IssuingState,
		Over12:               BoolToYesNo(dob.Before(time.Now().AddDate(-12, 0, 0))),
		Over16:               BoolToYesNo(dob.Before(time.Now().AddDate(-16, 0, 0))),
		Over18:               BoolToYesNo(dob.Before(time.Now().AddDate(-18, 0, 0))),
		Over21:               BoolToYesNo(dob.Before(time.Now().AddDate(-21, 0, 0))),
		Over65:               BoolToYesNo(dob.Before(time.Now().AddDate(-65, 0, 0))),
		ActiveAuthentication: BoolToYesNo(activeAuth),
	}

	if len(pngs) > 0 {
		request.Photo = pngs[0]
	}

	return request, nil
}

func BoolToYesNo(value bool) string {
	if value {
		return "Yes"
	}
	return "No"
}

func ParseDateTime(dateStr string) (time.Time, error) {
	// Parse date in yymmdd format
	if len(dateStr) != 6 {
		return time.Time{}, fmt.Errorf("invalid date format: %s", dateStr)
	}
	layout := "060102" // "06" for year, "01" for month, "02" for day

	parsedDate, err := time.Parse(layout, dateStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("error parsing date: %w", err)
	}
	return parsedDate, nil
}
