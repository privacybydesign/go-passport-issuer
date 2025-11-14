package document

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
	// Germany has D instead of the expected DEU.
	"D", "GRC", "HUN", "IRL", "ITA",
	"LVA", "LTU", "LUX", "MLT", "NLD",
	"POL", "PRT", "ROU", "SVK", "SVN",
	"ESP", "SWE",
}

// parseOptionalDataGroup parses an optional data group and logs errors gracefully
func parseOptionalDataGroup[T any](dgName string, data []byte, parseFunc func([]byte) (*T, error)) *T {
	result, err := parseFunc(data)
	if err != nil {
		log.Info.Printf("Skipping %s due to parsing error: %v", dgName, err)
		return nil
	}
	return result
}

func parsePassportDGs(doc *document.Document, dataGroups map[string]string) error {
	var err error

	for dg := range dataGroups {
		dataGroupBytes := utils.HexToBytes(dataGroups[dg])

		switch dg {
		case "DG1":
			doc.Mf.Lds1.Dg1, err = document.NewDG1(dataGroupBytes)
			if err != nil {
				return fmt.Errorf("failed to create DG1 (mandatory): %w", err)
			}
		case "DG2":
			doc.Mf.Lds1.Dg2, err = document.NewDG2(dataGroupBytes)
			if err != nil {
				return fmt.Errorf("failed to create DG2 (mandatory): %w", err)
			}
		case "DG7":
			doc.Mf.Lds1.Dg7 = parseOptionalDataGroup("DG7", dataGroupBytes, document.NewDG7)
		case "DG11":
			doc.Mf.Lds1.Dg11 = parseOptionalDataGroup("DG11", dataGroupBytes, document.NewDG11)
		case "DG12":
			doc.Mf.Lds1.Dg12 = parseOptionalDataGroup("DG12", dataGroupBytes, document.NewDG12)
		case "DG13":
			doc.Mf.Lds1.Dg13 = parseOptionalDataGroup("DG13", dataGroupBytes, document.NewDG13)
		case "DG14":
			doc.Mf.Lds1.Dg14 = parseOptionalDataGroup("DG14", dataGroupBytes, document.NewDG14)
		case "DG15":
			// DG15 is mandatory if provided
			doc.Mf.Lds1.Dg15, err = document.NewDG15(dataGroupBytes)
			if err != nil {
				return fmt.Errorf("failed to create DG15 (mandatory if provided): %w", err)
			}
		case "DG16":
			doc.Mf.Lds1.Dg16 = parseOptionalDataGroup("DG16", dataGroupBytes, document.NewDG16)
		default:
			return fmt.Errorf("unsupported data group: %s", dg)
		}
	}

	// Validate mandatory DGs
	if doc.Mf.Lds1.Dg1 == nil {
		return fmt.Errorf("DG1 is mandatory but was not provided")
	}
	if doc.Mf.Lds1.Dg2 == nil {
		return fmt.Errorf("DG2 is mandatory but was not provided")
	}

	return nil
}

func PassiveAuthenticationPassport(data models.ValidationRequest, certPool cms.CertPool) (doc document.Document, err error) {
	log.Info.Printf("Starting passive authentication for passports")

	if len(data.DataGroups) == 0 {
		return document.Document{}, fmt.Errorf("no data groups found")
	}

	if data.EFSOD == "" {
		return document.Document{}, fmt.Errorf("EF_SOD is missing in the validation request")
	}

	log.Info.Printf("Constructing document from data groups")

	var sodFileBytes = utils.HexToBytes(data.EFSOD)
	doc.Mf.Lds1.Sod, err = document.NewSOD(sodFileBytes)
	if err != nil {
		return document.Document{}, fmt.Errorf("failed to create SOD: %w", err)
	}

	// Type-specific: DG parsing
	err = parsePassportDGs(&doc, data.DataGroups)
	if err != nil {
		return document.Document{}, fmt.Errorf("failed to parse passport DGs: %w", err)
	}
	log.Info.Printf("Starting passive authentication for passport with issuing state: %s", doc.Mf.Lds1.Dg1.Mrz.IssuingState)

	err = passiveauth.PassiveAuth(&doc, certPool)
	if err != nil {
		return document.Document{}, fmt.Errorf("unexpected error: %s", err)
	}

	return doc, nil

}

func ActiveAuthentication(data models.ValidationRequest, doc document.Document) (bool, error) {
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
	dob, err = ParseDateOfBirth(doc.Mf.Lds1.Dg1.Mrz.DateOfBirth)
	if err != nil {
		return models.PassportData{}, fmt.Errorf("failed to parse date of birth: %w", err)
	}

	log.Info.Printf("Parsing date of expiry")
	doe, err = ParseExpiryDate(doc.Mf.Lds1.Dg1.Mrz.DateOfExpiry)
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

func ParseExpiryDate(dateStr string) (time.Time, error) {
	// Parse date in yymmdd format
	if len(dateStr) != 6 {
		return time.Time{}, fmt.Errorf("invalid date format: %s", dateStr)
	}
	layout := "060102" // "06" for year, "01" for month, "02" for day

	parsedDate, err := time.Parse(layout, dateStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("error parsing date: %w", err)
	}

	// arbitrarily determine that a date more than 30 years ago
	// gets added 100 years
	if parsedDate.Before(time.Now().AddDate(-30, 0, 0)) {
		parsedDate = parsedDate.AddDate(100, 0, 0)
	}

	return parsedDate, nil
}

func ParseDateOfBirth(dateStr string) (time.Time, error) {
	// Parse date in yymmdd format
	if len(dateStr) != 6 {
		return time.Time{}, fmt.Errorf("invalid date format: %s", dateStr)
	}
	layout := "060102" // "06" for year, "01" for month, "02" for day

	parsedDate, err := time.Parse(layout, dateStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("error parsing date: %w", err)
	}

	// Dates are stored in passports with only two digits for the year,
	// so when someone is born in 1950, only the 50 part is stored.
	// The Go time parser turns this into 2050 for some reason.
	// To combat this we determine if the (parsed) birth year is higher than the current year.
	// If it is we'll subtract 100 years from it.
	if parsedDate.After(time.Now()) {
		parsedDate = parsedDate.AddDate(-100, 0, 0)
	}

	return parsedDate, nil
}
