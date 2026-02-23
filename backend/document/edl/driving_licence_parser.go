package edl

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"go-passport-issuer/images"
	"log/slog"
	"strconv"
	"time"

	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
	"golang.org/x/text/encoding/charmap"
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
func ParseEDLDocument(dataGroups map[string]string, sodHex string) (*DrivingLicenceDocument, error) {
	doc := &DrivingLicenceDocument{}

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
			return nil, fmt.Errorf("failed to parse DG6: %w", err)
		}
		doc.Dg6 = dg6
	} else {
		return nil, fmt.Errorf("DG6 is mandatory but not provided")
	}

	// Parse DG13
	if dg13Hex, exists := dataGroups["DG13"]; exists {
		dg13Bytes := utils.HexToBytes(dg13Hex)
		pubKeyBytes, err := ExtractDG13PublicKeyInfo(dg13Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DG13: %w", err)
		}
		doc.Dg13 = &DG13{
			RawData:              dg13Bytes,
			SubjectPublicKeyInfo: pubKeyBytes,
		}
	}

	return doc, nil
}

func ParseEDLDG6(dg6Bytes []byte) (*DG6, error) {
	if len(dg6Bytes) == 0 {
		return nil, fmt.Errorf("DG6 is empty")
	}

	nodes, err := tlv.Decode(dg6Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode DG6 TLV: %w", err)
	}

	outerNode := nodes.NodeByTag(0x75)
	if !outerNode.IsValidNode() {
		return nil, fmt.Errorf("DG6 outer tag (0x75) not found")
	}

	biometricGroupNode := outerNode.NodeByTag(0x7F61)
	if !biometricGroupNode.IsValidNode() {
		return nil, fmt.Errorf("biometric group tag (0x7F61) not found")
	}

	biometricInfoNode := biometricGroupNode.NodeByTag(0x7F60)
	if !biometricInfoNode.IsValidNode() {
		return nil, fmt.Errorf("biometric info template (0x7F60) not found")
	}

	bdbNode := biometricInfoNode.NodeByTag(0x5F2E)
	if !bdbNode.IsValidNode() {
		return nil, fmt.Errorf("BDB tag (0x5F2E) not found")
	}

	facialData := bdbNode.Value()

	// Check for "FAC\0" header
	if len(facialData) < 4 || !bytes.Equal(facialData[:4], []byte{0x46, 0x41, 0x43, 0x00}) {
		// No FAC header, so return raw data
		return &DG6{
			RawData: dg6Bytes,
			ImageContainer: images.ImageContainer{
				ImageData: facialData,
			},
		}, nil
	}
	// Parse FAC structure to extract image
	offset := 4 // Skip "FAC\0"

	// check if there are at least 40 bytes left after this point
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

	// check if there are at least 14 bytes left after this point
	if len(facialData) < offset+14 {
		return nil, fmt.Errorf("FAC data too short for image header")
	}

	offset += 1 // face image type (1 byte)

	// Read image data type to determine JPEG vs JPEG2000
	imageDataType := int(facialData[offset])
	offset += 1

	offset += 2 // image width (2 bytes)
	offset += 2 // image height (2 bytes)
	offset += 1 // image color space (1 byte)
	offset += 1 // source type (1 byte)
	offset += 2 // device type (2 bytes)
	offset += 2 // quality (2 bytes)

	// Rest is the actual image data
	imageData := facialData[offset:]

	return &DG6{
		RawData: dg6Bytes,
		ImageContainer: images.ImageContainer{
			ImageData:     imageData,
			ImageDataType: &imageDataType,
		},
	}, nil
}

func decodeLatin1(bytes []byte) (string, error) {
	result, err := charmap.ISO8859_1.NewDecoder().Bytes(bytes)
	if err != nil {
		return "", err
	}
	return string(result), nil
}

func ParseEDLDG1(dg1Bytes []byte) (*DG1, error) {
	if len(dg1Bytes) == 0 {
		return nil, fmt.Errorf("DG1 is empty")
	}

	// Decode outer structure
	nodes, err := tlv.Decode(dg1Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode DG1 TLV: %w", err)
	}

	// Navigate to 0x61 -> 0x5F02
	rootNode := nodes.NodeByTag(DG1_OUTER_TAG)
	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("DG1 outer tag (0x61) not found")
	}

	mainNode := rootNode.NodeByTag(DG1_MAIN_TAG)
	if !mainNode.IsValidNode() {
		return nil, fmt.Errorf("DG1 main container (0x5F02) not found")
	}

	// Decode the VALUE of 0x5F02 as it contains nested TLVs
	personalDataTLV, err := tlv.Decode(mainNode.Value())
	if err != nil {
		return nil, fmt.Errorf("failed to decode personal details TLV: %w", err)
	}

	dg1 := &DG1{
		RawData: dg1Bytes,
	}

	// Extract each field
	if node := personalDataTLV.NodeByTag(ISSUING_MEMBER_STATE); node.IsValidNode() {
		dg1.IssuingMemberState, err = decodeLatin1(node.Value())
		if err != nil {
			return nil, fmt.Errorf("failed to decode issuing member state: %w", err)
		}
	}
	if node := personalDataTLV.NodeByTag(HOLDER_SURNAME); node.IsValidNode() {
		dg1.HolderSurname, err = decodeLatin1(node.Value())
		if err != nil {
			return nil, fmt.Errorf("failed to decode holder surname: %w", err)
		}
	}
	if node := personalDataTLV.NodeByTag(HOLDER_OTHER_NAME); node.IsValidNode() {
		dg1.HolderFirstName, err = decodeLatin1(node.Value())
		if err != nil {
			return nil, fmt.Errorf("failed to decode holder first name: %w", err)
		}
	}
	if node := personalDataTLV.NodeByTag(PLACE_OF_BIRTH); node.IsValidNode() {
		dg1.PlaceOfBirth, err = decodeLatin1(node.Value())
		if err != nil {
			return nil, fmt.Errorf("failed to decode place of birth: %w", err)
		}
	}
	if node := personalDataTLV.NodeByTag(ISSUING_AUTHORITY); node.IsValidNode() {
		dg1.IssuingAuthority, err = decodeLatin1(node.Value())
		if err != nil {
			return nil, fmt.Errorf("failed to decode issuing authority: %w", err)
		}
	}
	if node := personalDataTLV.NodeByTag(DOCUMENT_NUMBER); node.IsValidNode() {
		dg1.DocumentNumber, err = decodeLatin1(node.Value())
		if err != nil {
			return nil, fmt.Errorf("failed to decode document number: %w", err)
		}
	}

	// Parse BCD-encoded dates
	if node := personalDataTLV.NodeByTag(DATE_OF_BIRTH); node.IsValidNode() {
		dg1.DateOfBirth, err = parseBCDDate(node.Value())
		if err != nil {
			return nil, fmt.Errorf("failed to parse top-level date of birth (tag 0x5F06): %w", err)
		}
	}
	if node := personalDataTLV.NodeByTag(DATE_OF_ISSUE); node.IsValidNode() {
		dg1.DateOfIssue, err = parseBCDDate(node.Value())
		if err != nil {
			return nil, fmt.Errorf("failed to parse top-level date of issue (tag 0x5F0A): %w", err)
		}
	}
	if node := personalDataTLV.NodeByTag(DATE_OF_EXPIRY); node.IsValidNode() {
		dg1.DateOfExpiry, err = parseBCDDate(node.Value())
		if err != nil {
			return nil, fmt.Errorf("failed to parse top-level date of expiry (tag 0x5F0B): %w", err)
		}
	}

	// Parse categories (0x7F63) - directly under 0x61
	secondaryNode := rootNode.NodeByTag(DG1_SECONDARY_TAG)

	if !secondaryNode.IsValidNode() {
		dg1.Categories = []DrivingLicenseCategory{}
		return dg1, nil
	}

	const semicolonByte = 0x3B

	// Get all 0x87 category tags
	// Per ISO 18013-2:2008, category data is:
	//   <name><0x3B><4B issue BCD><0x3B><4B expiry BCD>[<0x3B><restrictions>...]
	// We find only the first semicolon and use fixed offsets for the two BCD dates.
	// Note: Some licenses (e.g., converted foreign licenses) may have an empty issue date,
	// represented by two consecutive semicolons: <name><0x3B><0x3B><4B expiry BCD>
	for i := 1; ; i++ {
		categoryNode := secondaryNode.NodeByTagOccur(CATEGORY_TAG, i)
		if !categoryNode.IsValidNode() {
			break
		}

		categoryData := categoryNode.Value()

		// Find the first semicolon (separates category name from BCD dates)
		firstSemicolon := -1
		for j, b := range categoryData {
			if b == semicolonByte {
				firstSemicolon = j
				break
			}
		}

		if firstSemicolon == -1 {
			slog.Warn("skipping category: no semicolon found",
				"index", i,
				"dataLen", len(categoryData))
			continue
		}

		categoryName := string(categoryData[0:firstSemicolon])

		var issueDate time.Time
		var expiryDate time.Time
		var err error

		// Check if issue date is empty (indicated by consecutive semicolons)
		if len(categoryData) > firstSemicolon+1 && categoryData[firstSemicolon+1] == semicolonByte {
			// Empty issue date: <name><0x3B><0x3B><4B expiry BCD>
			// Need at least: firstSemicolon + 1 (first sep) + 1 (second sep) + 4 (expiry BCD) = 6 bytes after name
			if len(categoryData) < firstSemicolon+6 {
				slog.Warn("skipping category: insufficient data for expiry date after empty issue date",
					"category", categoryName,
					"dataLen", len(categoryData))
				continue
			}
			expiryDateBCD := categoryData[firstSemicolon+2 : firstSemicolon+6]
			expiryDate, err = parseBCDDate(expiryDateBCD)
			if err != nil {
				slog.Warn("skipping category: failed to parse expiry date",
					"category", categoryName,
					"error", err)
				continue
			}
			// issueDate remains zero value
		} else {
			// Standard format: <name><0x3B><4B issue BCD><0x3B><4B expiry BCD>
			// Need at least: firstSemicolon + 1 (sep) + 4 (issue BCD) + 1 (sep) + 4 (expiry BCD) = 10 bytes after name
			if len(categoryData) < firstSemicolon+10 {
				slog.Warn("skipping category: insufficient data after first semicolon",
					"category", categoryName,
					"dataLen", len(categoryData),
					"firstSemicolon", firstSemicolon)
				continue
			}
			issueDateBCD := categoryData[firstSemicolon+1 : firstSemicolon+5]
			expiryDateBCD := categoryData[firstSemicolon+6 : firstSemicolon+10]

			issueDate, err = parseBCDDate(issueDateBCD)
			if err != nil {
				slog.Warn("skipping category: failed to parse issue date",
					"category", categoryName,
					"error", err)
				continue
			}
			expiryDate, err = parseBCDDate(expiryDateBCD)
			if err != nil {
				slog.Warn("skipping category: failed to parse expiry date",
					"category", categoryName,
					"error", err)
				continue
			}
		}

		dg1.Categories = append(dg1.Categories, DrivingLicenseCategory{
			Category:     categoryName,
			DateOfIssue:  issueDate,
			DateOfExpiry: expiryDate,
		})
	}
	return dg1, nil
}

func ParseEDLDG5(dg5Bytes []byte) (*DG5, error) {
	nodes, err := tlv.Decode(dg5Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DG5 TLV: %w", err)
	}
	root := nodes.NodeByTag(0x67)
	if !root.IsValidNode() {
		return nil, fmt.Errorf("tag 0x67 not found in DG5")
	}

	imageTypeNode := root.NodeByTag(0x89)
	if !imageTypeNode.IsValidNode() {
		return nil, fmt.Errorf("tag 0x89 not found in DG5")
	}

	imageType := int(imageTypeNode.Value()[0])
	switch imageType {
	case 0x03:
		imageType = 0x00
	case 0x04:
		imageType = 0x01
	default:
		return nil, fmt.Errorf("invalid image type (%v) in DG5", imageType)
	}

	imageNode := root.NodeByTag(0x5f43)
	if !imageNode.IsValidNode() {
		return nil, fmt.Errorf("tag 0x5f43 not found in DG5")
	}

	imageData := imageNode.Value()

	return &DG5{
		RawData: dg5Bytes,
		Signature: images.ImageContainer{
			ImageDataType: &imageType,
			ImageData:     imageData,
		},
	}, nil
}

func ExtractDG13PublicKeyInfo(dg13Bytes []byte) ([]byte, error) {

	// Unwrap outer 0x6F tag
	nodes, err := tlv.Decode(dg13Bytes)
	if err != nil {
		return nil, err
	}

	// value of tag 0x6F is the SubjectPublicKeyInfo
	return nodes.NodeByTag(0x6F).Value(), nil
}

// isValidBCD checks that every nibble in the given byte slice is a valid BCD digit (0-9).
func isValidBCD(data []byte) bool {
	for _, b := range data {
		highNibble := (b >> 4) & 0x0F
		lowNibble := b & 0x0F
		if highNibble > 9 || lowNibble > 9 {
			return false
		}
	}
	return true
}

// parseBCDDate converts BCD-encoded bytes to time.Time
// Format: DDMMYYYY in BCD (4 bytes)
func parseBCDDate(bcd []byte) (time.Time, error) {
	if len(bcd) != 4 {
		return time.Time{}, fmt.Errorf("invalid BCD date length: %d", len(bcd))
	}

	if !isValidBCD(bcd) {
		return time.Time{}, fmt.Errorf("invalid BCD data: contains non-decimal nibble in %x", bcd)
	}

	// Convert BCD to string: each byte becomes 2 digits
	dateStr := hex.EncodeToString(bcd)

	// Parse as DDMMYYYY
	day, err := strconv.Atoi(dateStr[0:2])
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse day: %w", err)
	}

	month, err := strconv.Atoi(dateStr[2:4])
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse month: %w", err)
	}

	year, err := strconv.Atoi(dateStr[4:8])
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse year: %w", err)
	}

	return time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC), nil
}
