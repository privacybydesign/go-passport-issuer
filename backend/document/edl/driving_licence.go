package edl

import (
	"bytes"
	"fmt"
	mrtdDoc "go-passport-issuer/document"
	log "go-passport-issuer/logging"
	"go-passport-issuer/models"
	"strconv"
	"strings"
	"time"

	"github.com/gmrtd/gmrtd/activeauth"
	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/utils"
)

func parseDgNumber(dgName string) (int, error) {
	if !strings.HasPrefix(dgName, "DG") {
		return 0, fmt.Errorf("invalid DG name: %s", dgName)
	}

	num, err := strconv.Atoi(dgName[2:]) // Skip "DG" prefix
	if err != nil {
		return 0, fmt.Errorf("invalid DG number in %s: %w", dgName, err)
	}

	return num, nil
}
func PassiveAuthenticationEDL(data models.ValidationRequest, certPool *cms.CertPool) (err error) {

	if len(data.DataGroups) == 0 {
		return fmt.Errorf("no data groups found")
	}

	if data.EFSOD == "" {
		return fmt.Errorf("EF_SOD is missing in the validation request")
	}

	log.Info.Printf("Constructing EF.SOD from bytes")

	var doc document.Document
	var sodFileBytes = utils.HexToBytes(data.EFSOD)

	doc.Mf.Lds1.Sod, err = document.NewSOD(sodFileBytes)
	if err != nil {
		return fmt.Errorf("failed to create SOD: %w", err)
	}

	// Check if hash alg not null
	if doc.Mf.Lds1.Sod.LdsSecurityObject == nil ||
		doc.Mf.Lds1.Sod.LdsSecurityObject.HashAlgorithm.Algorithm == nil {
		return fmt.Errorf("SOD LDS security object hash algorithm not found")
	}
	hashAlgo := doc.Mf.Lds1.Sod.LdsSecurityObject.HashAlgorithm.Algorithm

	for dgName, dgHex := range data.DataGroups {
		dgBytes := utils.HexToBytes(dgHex)
		dgNum, err := parseDgNumber(dgName) // DgHash function requires dg number
		if err != nil {
			return err
		}

		computedHash, err := cryptoutils.CryptoHashByOid(hashAlgo, dgBytes)
		if err != nil {
			return fmt.Errorf("failed to hash %s: %w", dgName, err)
		}

		expectedHash := doc.Mf.Lds1.Sod.DgHash(dgNum)
		if len(expectedHash) == 0 {
			return fmt.Errorf("%s not in SOD", dgName)
		}

		if !bytes.Equal(computedHash, expectedHash) {
			return fmt.Errorf("%s hash mismatch", dgName)
		}
	}
	log.Info.Printf("passive auth succeeded")

	_, err = doc.Mf.Lds1.Sod.SD.Verify(*certPool)
	if err != nil {
		return fmt.Errorf("SOD signature verification failed: %w", err)
	}
	log.Info.Printf("verifying the request SOD against the certificate chain succeeded")

	return nil
}

func ActiveAuthenticationEDL(data models.ValidationRequest) (result bool, err error) {
	if data.Nonce == "" || data.ActiveAuthSignature == "" {
		return false, nil
	}

	dg13Hex, exists := data.DataGroups["DG13"]
	if !exists {
		return false, nil
	}

	dg13Bytes := utils.HexToBytes(dg13Hex)

	// Parse DG13 to extract the SubjectPublicKeyInfo
	pubKeyBytes, err := ExtractDG13PublicKeyInfo(dg13Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to extract public key from DG13: %w", err)
	}

	// NOTE: gmrtd is passport specific, so we get the public key from DG13 of eDL
	// and create a document with DG15 of key extracted from dg13
	// TODO: change this once gmrtd supports eDL groups as well
	doc := document.Document{}
	doc.Mf.Lds1.Dg15 = &document.DG15{
		SubjectPublicKeyInfoBytes: pubKeyBytes,
	}

	aaSigBytes := utils.HexToBytes(data.ActiveAuthSignature)
	nonceBytes := utils.HexToBytes(data.Nonce)

	activeAuth := activeauth.NewActiveAuth(nil, &doc)
	err = activeAuth.ValidateActiveAuthSignature(aaSigBytes, nonceBytes)
	if err != nil {
		return false, fmt.Errorf("failed to validate active authentication signature: %w", err)
	}

	return true, nil
}

func ToDrivingLicenceData(doc DrivingLicenceDocument, activeAuth bool) (request models.EDLData, err error) {
	pngs, err := doc.Dg6.ConvertToPNG()
	if err != nil {
		return models.EDLData{}, fmt.Errorf("failed to convert DG6 image to PNG: %w", err)
	}

	var dob = doc.Dg1.DateOfBirth
	request = models.EDLData{
		DocumentNumber:       doc.Dg1.DocumentNumber,
		FirstName:            doc.Dg1.HolderFirstName,
		LastName:             doc.Dg1.HolderSurname,
		IssuingMemberState:   doc.Dg1.IssuingMemberState,
		IssuingAuthority:     doc.Dg1.IssuingAuthority,
		DateOfBirth:          doc.Dg1.DateOfBirth,
		YearOfBirth:          dob.Format("2006"),
		PlaceOfBirth:         doc.Dg1.PlaceOfBirth,
		DateOfExpiry:         doc.Dg1.DateOfExpiry,
		Over12:               mrtdDoc.BoolToYesNo(dob.Before(time.Now().AddDate(-12, 0, 0))),
		Over16:               mrtdDoc.BoolToYesNo(dob.Before(time.Now().AddDate(-16, 0, 0))),
		Over18:               mrtdDoc.BoolToYesNo(dob.Before(time.Now().AddDate(-18, 0, 0))),
		Over21:               mrtdDoc.BoolToYesNo(dob.Before(time.Now().AddDate(-21, 0, 0))),
		Over65:               mrtdDoc.BoolToYesNo(dob.Before(time.Now().AddDate(-65, 0, 0))),
		ActiveAuthentication: mrtdDoc.BoolToYesNo(activeAuth),
	}

	if len(pngs) > 0 {
		request.Photo = pngs[0]
	}

	return request, nil
}
