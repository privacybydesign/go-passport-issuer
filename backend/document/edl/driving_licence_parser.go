package edl

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
)

// TLV tag constants for DG1
const (
	DG1_OUTER_TAG        = 0x61
	DG1_MAIN_TAG         = 0x5F02
	DG1_SECONDARY_TAG    = 0x7F63
	ISSUING_MEMBER_STATE = 0x5F03
	HOLDER_SURNAME       = 0x5F04
	HOLDER_OTHER_NAME    = 0x5F05
	DATE_OF_BIRTH        = 0x5F06
	PLACE_OF_BIRTH       = 0x5F07
	DATE_OF_ISSUE        = 0x5F0A
	DATE_OF_EXPIRY       = 0x5F0B
	ISSUING_AUTHORITY    = 0x5F0C
	DOCUMENT_NUMBER      = 0x5F0E
	CATEGORY_TAG         = 0x87
)

// ParseEDLDocument parses all eDL data groups into a structured document
func ParseEDLDocument(dataGroups map[string]string, sodHex string) (*EDLDocument, error) {
	doc := &EDLDocument{}

	// Parse SOD
	if sodHex != "" {
		sodBytes := utils.HexToBytes(sodHex)
		var err error
		doc.Sod, err = document.NewSOD(sodBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse SOD: %w", err)
		}
	}

	// Parse DG1 (mandatory)
	if dg1Hex, exists := dataGroups["DG1"]; exists {
		dg1Bytes := utils.HexToBytes(dg1Hex)
		dg1, err := ParseEDLDG1(dg1Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DG1: %w", err)
		}
		doc.Dg1 = dg1
	} else {
		return nil, fmt.Errorf("DG1 is mandatory but not provided")
	}

	// Parse DG6 (mandatory)
	if dg6Hex, exists := dataGroups["DG6"]; exists {
		dg6Bytes := utils.HexToBytes(dg6Hex)
		dg6, err := ParseEDLDG6(dg6Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DG1: %w", err)
		}
		doc.Dg6 = dg6
	} else {
		return nil, fmt.Errorf("DG1 is mandatory but not provided")
	}

	// Parse DG13
	if dg13Hex, exists := dataGroups["DG13"]; exists {
		dg13Bytes := utils.HexToBytes(dg13Hex)
		pubKeyBytes, err := ExtractDG13PublicKeyInfo(dg13Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DG13: %w", err)
		}
		doc.Dg13 = &EDLDG13{
			RawData:              dg13Bytes,
			SubjectPublicKeyInfo: pubKeyBytes,
		}
	}

	return doc, nil
}

func ParseEDLDG6(dg6Bytes []byte) (*EDLDG6, error) {
	if len(dg6Bytes) < 1 {
		return nil, fmt.Errorf("DG6 is empty")
	}

	nodes, err := tlv.Decode(dg6Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode DG6 TLV: %w", err)
	}

	outerNode := nodes.GetNode(0x75)
	if !outerNode.IsValidNode() {
		return nil, fmt.Errorf("DG6 outer tag (0x75) not found")
	}

	biometricGroupNode := outerNode.GetNode(0x7F61)
	if !biometricGroupNode.IsValidNode() {
		return nil, fmt.Errorf("Biometric group tag (0x7F61) not found")
	}

	biometricInfoNode := biometricGroupNode.GetNode(0x7F60)
	if !biometricInfoNode.IsValidNode() {
		return nil, fmt.Errorf("Biometric info template (0x7F60) not found")
	}

	bdbNode := biometricInfoNode.GetNode(0x5F2E)
	if !bdbNode.IsValidNode() {
		return nil, fmt.Errorf("BDB tag (0x5F2E) not found")
	}

	facialData := bdbNode.GetValue()

	// Check for "FAC\0" header
	if len(facialData) < 4 ||
		facialData[0] != 0x46 || facialData[1] != 0x41 ||
		facialData[2] != 0x43 || facialData[3] != 0x00 {
		// No FAC header, return raw data
		return &EDLDG6{
			RawData:   dg6Bytes,
			ImageData: facialData,
			ImageType: "JPEG",
		}, nil
	}

	// Parse FAC structure to extract image
	offset := 4 // Skip "FAC\0"

	if len(facialData) < offset+40 {
		return nil, fmt.Errorf("FAC data too short")
	}

	// Skip fixed header fields (36 bytes total after FAC\0)
	offset += 4 // version (4 bytes)
	offset += 4 // length of record (4 bytes)
	offset += 2 // number of facial images (2 bytes)
	offset += 4 // facial record data length (4 bytes)

	// Read number of feature points (2 bytes)
	nrFeaturePoints := int(facialData[offset])<<8 | int(facialData[offset+1])
	offset += 2

	offset += 1 // gender (1 byte)
	offset += 1 // eye color (1 byte)
	offset += 1 // hair color (1 byte)
	offset += 3 // feature mask (3 bytes)
	offset += 2 // expression (2 bytes)
	offset += 3 // pose angle (3 bytes)
	offset += 3 // pose angle uncertainty (3 bytes)

	// Skip feature points (8 bytes each)
	offset += nrFeaturePoints * 8

	if len(facialData) < offset+14 {
		return nil, fmt.Errorf("FAC data too short for image header")
	}

	offset += 1 // face image type (1 byte)

	// Read image data type to determine JPEG vs JPEG2000
	imageDataType := facialData[offset]
	imageType := "JPEG"
	if imageDataType == 1 {
		imageType = "JPEG2000"
	}
	offset += 1

	offset += 2 // image width (2 bytes)
	offset += 2 // image height (2 bytes)
	offset += 1 // image color space (1 byte)
	offset += 1 // source type (1 byte)
	offset += 2 // device type (2 bytes)
	offset += 2 // quality (2 bytes)

	// Rest is the actual image data
	imageData := facialData[offset:]

	return &EDLDG6{
		RawData:   dg6Bytes,
		ImageData: imageData,
		ImageType: imageType,
	}, nil
}

func ParseEDLDG1(dg1Bytes []byte) (*EDLDG1, error) {
	if len(dg1Bytes) < 1 {
		return nil, fmt.Errorf("DG1 is empty")
	}

	// Decode outer structure
	nodes, err := tlv.Decode(dg1Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode DG1 TLV: %w", err)
	}

	// Navigate to 0x61 -> 0x5F02
	rootNode := nodes.GetNode(DG1_OUTER_TAG)
	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("DG1 outer tag (0x61) not found")
	}

	mainNode := rootNode.GetNode(DG1_MAIN_TAG)
	if !mainNode.IsValidNode() {
		return nil, fmt.Errorf("DG1 main container (0x5F02) not found")
	}

	// Decode the VALUE of 0x5F02 as it contains nested TLVs
	personalDataTLV, err := tlv.Decode(mainNode.GetValue())
	if err != nil {
		return nil, fmt.Errorf("failed to decode personal details TLV: %w", err)
	}

	dg1 := &EDLDG1{
		RawData: dg1Bytes,
	}

	// Extract each field
	if node := personalDataTLV.GetNode(ISSUING_MEMBER_STATE); node.IsValidNode() {
		dg1.IssuingMemberState = string(node.GetValue())
	}
	if node := personalDataTLV.GetNode(HOLDER_SURNAME); node.IsValidNode() {
		dg1.HolderSurname = string(node.GetValue())
	}
	if node := personalDataTLV.GetNode(HOLDER_OTHER_NAME); node.IsValidNode() {
		dg1.HolderOtherName = string(node.GetValue())
	}
	if node := personalDataTLV.GetNode(PLACE_OF_BIRTH); node.IsValidNode() {
		dg1.PlaceOfBirth = string(node.GetValue())
	}
	if node := personalDataTLV.GetNode(ISSUING_AUTHORITY); node.IsValidNode() {
		dg1.IssuingAuthority = string(node.GetValue())
	}
	if node := personalDataTLV.GetNode(DOCUMENT_NUMBER); node.IsValidNode() {
		dg1.DocumentNumber = string(node.GetValue())
	}

	// Parse BCD-encoded dates
	if node := personalDataTLV.GetNode(DATE_OF_BIRTH); node.IsValidNode() {
		dg1.DateOfBirth, _ = parseBCDDate(node.GetValue())
	}
	if node := personalDataTLV.GetNode(DATE_OF_ISSUE); node.IsValidNode() {
		dg1.DateOfIssue, _ = parseBCDDate(node.GetValue())
	}
	if node := personalDataTLV.GetNode(DATE_OF_EXPIRY); node.IsValidNode() {
		dg1.DateOfExpiry, _ = parseBCDDate(node.GetValue())
	}

	// Parse categories (0x7F63) - directly under 0x61
	secondaryNode := rootNode.GetNode(DG1_SECONDARY_TAG)
	if secondaryNode.IsValidNode() {
		// Get all 0x87 category tags
		for i := 1; ; i++ {
			categoryNode := secondaryNode.GetNodeByOccur(CATEGORY_TAG, i)
			if !categoryNode.IsValidNode() {
				break
			}

			categoryData := categoryNode.GetValue()

			// Find semicolons
			firstSemicolon := -1
			secondSemicolon := -1
			for j, b := range categoryData {
				if b == 0x3b {
					if firstSemicolon == -1 {
						firstSemicolon = j
					} else {
						secondSemicolon = j
						break
					}
				}
			}

			if firstSemicolon != -1 && secondSemicolon != -1 && len(categoryData) >= secondSemicolon+5 {
				categoryName := string(categoryData[0:firstSemicolon])
				issueDateBCD := categoryData[firstSemicolon+1 : firstSemicolon+5]
				expiryDateBCD := categoryData[secondSemicolon+1 : secondSemicolon+5]

				issueDate, _ := parseBCDDate(issueDateBCD)
				expiryDate, _ := parseBCDDate(expiryDateBCD)

				dg1.Categories = append(dg1.Categories, DrivingLicenseCategory{
					Category:     categoryName,
					DateOfIssue:  issueDate,
					DateOfExpiry: expiryDate,
				})
			}
		}
	} else {
		dg1.Categories = []DrivingLicenseCategory{}
	}

	return dg1, nil
}

func ExtractDG13PublicKeyInfo(dg13Bytes []byte) ([]byte, error) {

	// Unwrap outer 0x6F tag
	nodes, err := tlv.Decode(dg13Bytes)
	if err != nil {
		return nil, err
	}

	// value of tag 0x6F is the SubjectPublicKeyInfo
	return nodes.GetNode(0x6F).GetValue(), nil
}

// parseBCDDate converts BCD-encoded bytes to time.Time
// Format: DDMMYYYY in BCD (4 bytes)
func parseBCDDate(bcd []byte) (time.Time, error) {
	if len(bcd) != 4 {
		return time.Time{}, fmt.Errorf("invalid BCD date length: %d", len(bcd))
	}

	// Convert BCD to string: each byte becomes 2 digits
	dateStr := hex.EncodeToString(bcd)

	// Parse as DDMMYYYY
	day, _ := strconv.Atoi(dateStr[0:2])
	month, _ := strconv.Atoi(dateStr[2:4])
	year, _ := strconv.Atoi(dateStr[4:8])

	return time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC), nil
}
