package document

import (
	"bytes"
	"fmt"
	log "go-passport-issuer/logging"
	"go-passport-issuer/models"
	"strconv"
	"strings"

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
