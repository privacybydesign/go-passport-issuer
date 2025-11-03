package passport

import (
	"fmt"
	"go-passport-issuer/images"
	"go-passport-issuer/models"
	"strings"
	"time"

	log "go-passport-issuer/logging"

	"github.com/gmrtd/gmrtd/activeauth"
	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/passiveauth"
	"github.com/gmrtd/gmrtd/utils"
)

var euCountries = []string{
	"AUT", "BEL", "BGR", "HRV", "CYP",
	"CZE", "DNK", "EST", "FIN", "FRA",
	"DEU", "GRC", "HUN", "IRL", "ITA",
	"LVA", "LTU", "LUX", "MLT", "NLD",
	"POL", "PRT", "ROU", "SVK", "SVN",
	"ESP", "SWE",
}

func PassiveAuthentication(data models.PassportValidationRequest, certPool cms.CertPool) (doc document.Document, err error) {
	log.Info.Printf("Starting passive authentication")

	if len(data.DataGroups) == 0 {
		return document.Document{}, fmt.Errorf("no data groups found in passport data")
	}

	if data.EFSOD == "" {
		return document.Document{}, fmt.Errorf("EF_SOD is missing in passport data")
	}

	log.Info.Printf("Constructing document from data groups")

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
			// temporary logs -- should be removed!
			if doc.Mf.Lds1.Dg1 != nil {
				if doc.Mf.Lds1.Dg1.Mrz.Nationality == "HUN" {
					log.Info.Printf("DG7 raw data bytes for Hungarian passport: %x", dataGroupBytes)
				}
			}
			dg7, parseErr := document.NewDG7(dataGroupBytes)
			if parseErr != nil {
				log.Info.Printf("Skipping DG7 due to parsing error: %v", parseErr)
				continue
			}
			doc.Mf.Lds1.Dg7 = dg7
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

	log.Info.Printf("Starting passive authentication for issuing state: %s", doc.Mf.Lds1.Dg1.Mrz.IssuingState)

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

	log.Info.Printf("Starting active authentication signature validation")

	aaSigBytes := utils.HexToBytes(data.ActiveAuthSignature)
	nonceBytes := utils.HexToBytes(data.Nonce)

	activeauth := activeauth.NewActiveAuth(nil, &doc)
	err := activeauth.ValidateActiveAuthSignature(aaSigBytes, nonceBytes)
	if err != nil {
		return false, fmt.Errorf("failed to validate active authentication signature: %w", err)
	}
	return true, nil
}

func IsEuCitizen(nationality string) bool {
	for _, country := range euCountries {
		if strings.ToUpper(nationality) == country {
			return true
		}
	}
	return false
}

func ToPassportData(doc document.Document, activeAuth bool) (request models.PassportData, err error) {
	log.Info.Printf("Converting document to passport issuance request")

	var dob, doe time.Time
	log.Info.Printf("Parsing date of birth")
	dob, err = ParseDateTime(doc.Mf.Lds1.Dg1.Mrz.DateOfBirth)
	if err != nil {
		return models.PassportData{}, fmt.Errorf("failed to parse date of birth: %w", err)
	}

	log.Info.Printf("Parsing date of expiry")
	doe, err = ParseDateTime(doc.Mf.Lds1.Dg1.Mrz.DateOfExpiry)
	if err != nil {
		return models.PassportData{}, fmt.Errorf("failed to parse date of expiry: %w", err)
	}

	log.Info.Printf("Converting EF DG2 images to PNG")
	efDG2, err := images.NewEfDG2FromBytes(doc.Mf.Lds1.Dg2.RawData)
	if err != nil {
		return models.PassportData{}, fmt.Errorf("failed to create EfDG2: %w", err)
	}
	pngs, err := efDG2.ConvertToPNG()
	if err != nil {
		return models.PassportData{}, fmt.Errorf("failed to convert EF DG2 images to PNG: %w", err)
	}

	request = models.PassportData{
		DocumentNumber:       doc.Mf.Lds1.Dg1.Mrz.DocumentNumber,
		DocumentType:         doc.Mf.Lds1.Dg1.Mrz.DocumentCode,
		FirstName:            doc.Mf.Lds1.Dg1.Mrz.NameOfHolder.Secondary,
		LastName:             doc.Mf.Lds1.Dg1.Mrz.NameOfHolder.Primary,
		Nationality:          doc.Mf.Lds1.Dg1.Mrz.Nationality,
		IsEuCitizen:          BoolToYesNo(IsEuCitizen(doc.Mf.Lds1.Dg1.Mrz.Nationality)),
		DateOfBirth:          dob,
		YearOfBirth:          dob.Format("2006"),
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
