package passport_utils

import (
	"bytes"
	"crypto"
	"fmt"
	"go-passport-issuer/models"
	"log"
	"log/slog"
	"time"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/passiveauth"
	"github.com/gmrtd/gmrtd/utils"
)

func Validate(data models.PassportValidationRequest, certPool *cms.CombinedCertPool) (doc document.Document, err error) {
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

	if doc.Mf.Lds1.Dg15 != nil {
		isVerified := VerifyAASignature(data, doc)
		if !isVerified {
			return document.Document{}, fmt.Errorf("active authentication failed: signature was not verified")
		}

	}

	return doc, nil
}

// Verifies the response signature from the AA challenge received from the flutter app.
// The gmrtd library has functions that carry the whole AA and therefore the verification,
// which can't directly be used in our issuer since the flutter app is sending the ADPDU
//
//	commands and the issuer just receives a signature that is 8 bytes.
//
// We can make the internal function decodeF external and use it to decode the message, data and hashAlg
// https://github.com/gmrtd/gmrtd/blob/518f2cc2953aab118a176b9928616bf38f157df2/activeauth/active_auth.go#L32
func VerifyAASignature(reqData models.PassportValidationRequest, doc document.Document) bool {
	// the signature is a string hash, we first need to extract the bytes
	signatureBytes := utils.HexToBytes(reqData.Signature)
	nonceBytes := utils.HexToBytes(reqData.Nonce)
	if len(signatureBytes) != 8 {
		log.Printf("invalid signature length: %d", len(signatureBytes))
		return false
	}
	var subPubKeyInfo cms.SubjectPublicKeyInfo = cms.Asn1decodeSubjectPublicKeyInfo(doc.Mf.Lds1.Dg15.SubjectPublicKeyInfoBytes)
	var pubKey *cryptoutils.RsaPublicKey = subPubKeyInfo.GetRsaPubKey()
	f := cryptoutils.RsaDecryptWithPublicKey(signatureBytes, *pubKey)
	m1, d, hashAlg, err := decodeF(f)
	if err != nil {
		log.Printf("failed to decode F: %d", err)
		return false
	}

	// m is concat of m1 and m2 (rnd-ifd)
	var expD []byte
	{
		m := bytes.Clone(m1)
		m = append(m, nonceBytes...)
		expD = cryptoutils.CryptoHash(hashAlg, m)
	}

	return bytes.Equal(d, expD)

}

// Internal function from the activeauth of gmrtd library
func decodeF(f []byte) (m1 []byte, d []byte, hashAlg crypto.Hash, err error) {
	var tmpF []byte = bytes.Clone(f)

	slog.Debug("decodeF", "f", utils.BytesToHex(f))

	if len(tmpF) < 4 {
		return nil, nil, 0, fmt.Errorf("(decodeF) must have at least 4 bytes")
	}

	// should start with 0x6A
	if tmpF[0] != 0x6A {
		return nil, nil, 0, fmt.Errorf("(decodeF) must start with 0x6A")
	}
	tmpF = tmpF[1:]

	// detect hash from trailer
	{
		var trailerLen int

		switch tmpF[len(tmpF)-1] {
		case 0xBC:
			// SHA-1
			hashAlg = crypto.SHA1
			trailerLen = 1
		case 0xCC:
			// trailer is 2 bytes (i.e. xxCC)
			switch tmpF[len(tmpF)-2] {
			case 0x38:
				hashAlg = crypto.SHA224
			case 0x34:
				hashAlg = crypto.SHA256
			case 0x36:
				hashAlg = crypto.SHA384
			case 0x35:
				hashAlg = crypto.SHA512
			default:
				return nil, nil, 0, fmt.Errorf("(decodeF) unknown hashAlg for 2-byte trailer (%x,CC)", tmpF[len(tmpF)-2])
			}
			trailerLen = 2
		default:
			return nil, nil, 0, fmt.Errorf("(decodeF) unable to determine hash alg from trailer byte (lastByte:%x)", tmpF[len(tmpF)-1])
		}

		// remove the trailer byte(s)
		tmpF = tmpF[:len(tmpF)-trailerLen]
	}

	var digestSize int = cryptoutils.CryptoHashDigestSize(hashAlg)

	// verify we have enough bytes remaining for the digest
	if len(tmpF) < digestSize {
		return nil, nil, 0, fmt.Errorf("(decodeF) insufficient bytes remaining to extract digest (req:%d) (rem:%d)", digestSize, len(tmpF))
	}

	// extract digest (d) and m1
	d = bytes.Clone(tmpF[len(tmpF)-digestSize:])
	m1 = bytes.Clone(tmpF[:len(tmpF)-digestSize])

	slog.Debug("decodeF", "m1", utils.BytesToHex(m1), "d", utils.BytesToHex(d), "hashAlg", hashAlg)

	return
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

	// var photo, err = PhotodToBase64(doc.Mf.Lds1.Dg2.RawData)
	// if err != nil {
	// 	return models.PassportIssuanceRequest{}, fmt.Errorf("failed to convert photo to base64: %w", err)
	// }

	request = models.PassportIssuanceRequest{
		Photo:                "",
		DocumentNumber:       doc.Mf.Lds1.Dg1.Mrz.DocumentNumber,
		DocumentType:         doc.Mf.Lds1.Dg1.Mrz.DocumentCode,
		FirstName:            doc.Mf.Lds1.Dg1.Mrz.NameOfHolder.Secondary,
		LastName:             doc.Mf.Lds1.Dg1.Mrz.NameOfHolder.Primary,
		Nationality:          doc.Mf.Lds1.Dg1.Mrz.Nationality,
		DateOfBirth:          dob,
		DateOfExpiry:         doe,
		Gender:               doc.Mf.Lds1.Dg1.Mrz.Sex,
		Country:              doc.Mf.Lds1.Dg1.Mrz.IssuingState,
		Over12:               dob.Before(time.Now().AddDate(-12, 0, 0)),
		Over16:               dob.Before(time.Now().AddDate(-16, 0, 0)),
		Over18:               dob.Before(time.Now().AddDate(-18, 0, 0)),
		Over21:               dob.Before(time.Now().AddDate(-21, 0, 0)),
		Over65:               dob.Before(time.Now().AddDate(-65, 0, 0)),
		ActiveAuthentication: activeAuth,
	}
	return request, nil
}

// func PhotoToBase64(photo []byte) (string, error) {
// 	if len(photo) == 0 {
// 		return "", fmt.Errorf("photo data is empty")
// 	}
// 	return utils.Base64Encode(photo), nil
// }

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
