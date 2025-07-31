package main

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"strconv"
)

// AlgorithmIdentifier represents the hash algorithm
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// HashEntry represents each hash entry with ID and hash value
type HashEntry struct {
	ID   int    // INTEGER (no tag needed - uses default)
	Hash []byte // OCTET STRING (no tag needed - uses default)
}

// FinalSequence represents the last sequence with two printable strings
type FinalSequence struct {
	String1 string `asn1:"printable"`
	String2 string `asn1:"printable"`
}

// LDSContent represents the complete structure
type LDSContent struct {
	Version       int                 // INTEGER (no tag needed - uses default)
	HashAlgorithm AlgorithmIdentifier // SEQUENCE (no tag needed - uses default)
	HashList      []HashEntry         // SEQUENCE OF (no tag needed - uses default)
	Final         FinalSequence       // SEQUENCE (no tag needed - uses default)
}

// PassportData represents the main structure for passport reading results
type PassportData struct {
	DataGroups map[string]string `json:"data_groups"`
	EFSOD      string            `json:"EF_SOD"`
}

var oidToHash = map[string]crypto.Hash{
	"1.3.14.3.2.26":          crypto.SHA1,
	"2.16.840.1.101.3.4.2.1": crypto.SHA256,
	"2.16.840.1.101.3.4.2.2": crypto.SHA384,
	"2.16.840.1.101.3.4.2.3": crypto.SHA512,
	"2.16.840.1.101.3.4.2.4": crypto.SHA224,
	"2.16.840.1.101.3.4.2.5": crypto.SHA512_224,
	"2.16.840.1.101.3.4.2.6": crypto.SHA512_256,
}

func main() {
	// Read the DER file
	if len(os.Args) != 3 {
		log.Fatal("Usage: extract_dg_hashes lds_content.der sample.json")
	}

	sodFileName := os.Args[1]
	sodData, err := os.ReadFile(sodFileName)
	if err != nil {
		log.Fatal("Error reading file:", err)
	}

	jsonfile := os.Args[2]
	jsonData, err := os.ReadFile(jsonfile)
	if err != nil {
		log.Fatal("Error reading file:", err)
	}

	ldsContent := getLDSContentFromSod(sodData)
	passportData := getPassportDataFromJson(jsonData)

	// Print the parsed data
	log.Printf("Version: %d", ldsContent.Version)
	log.Printf("Hash Algorithm OID: %s", ldsContent.HashAlgorithm.Algorithm.String())

	hashAlg, ok := hashAlgorithmFromOID(ldsContent.HashAlgorithm.Algorithm)
	if !ok {
		log.Fatalf("Unsupported hash algorithm OID: %s", ldsContent.HashAlgorithm.Algorithm.String())
	}

	compareHashEntries(ldsContent, passportData, hashAlg)
}

func compareHashEntries(ldsContent LDSContent, passportData PassportData, hashAlg crypto.Hash) {
	var err error
	log.Println("\nHash Entries:")
	for _, entry := range ldsContent.HashList {
		log.Printf("  ID: %d, Hash: %s", entry.ID, hex.EncodeToString(entry.Hash))

		var dgData = passportData.DataGroups["DG"+strconv.Itoa(entry.ID)]
		if dgData == "" {
			log.Printf("  DG%d not found in passport data", entry.ID)
			continue
		}

		var dgBytes, _ = hex.DecodeString(dgData)
		if err != nil {
			log.Printf("  Error decoding DG%d: %v", entry.ID, err)
			continue
		}
		var dgHash, _ = hashData(hashAlg, dgBytes)
		equal := bytes.Equal(entry.Hash, dgHash)
		if !equal {
			log.Printf("  Hash mismatch for DG%d: expected %s, got %s", entry.ID, hex.EncodeToString(entry.Hash), hex.EncodeToString(dgHash))
		} else {
			log.Printf("  Hash matches for DG%d", entry.ID)
		}
	}
}

func hashAlgorithmFromOID(oid asn1.ObjectIdentifier) (crypto.Hash, bool) {
	hash, ok := oidToHash[oid.String()]
	return hash, ok
}

func hashData(hashAlg crypto.Hash, data []byte) ([]byte, error) {
	switch hashAlg {
	case crypto.SHA1:
		h := sha1.Sum(data)
		return h[:], nil
	case crypto.SHA224:
		h := sha256.Sum224(data)
		return h[:], nil
	case crypto.SHA256:
		h := sha256.Sum256(data)
		return h[:], nil
	case crypto.SHA384:
		h := sha512.Sum384(data)
		return h[:], nil
	case crypto.SHA512:
		h := sha512.Sum512(data)
		return h[:], nil
	case crypto.SHA512_224:
		h := sha512.Sum512_224(data)
		return h[:], nil
	case crypto.SHA512_256:
		h := sha512.Sum512_256(data)
		return h[:], nil
	default:
		log.Fatal("Unsupported hash algorithm:", hashAlg)
		return nil, nil
	}
}

func getLDSContentFromSod(data []byte) LDSContent {
	// Try the automatic parsing first
	log.Println("=== Attempting Automatic Parsing ===")
	var ldsContent LDSContent
	_, err := asn1.Unmarshal(data, &ldsContent)
	if err != nil {
		log.Fatal("Automatic parsing failed: %v\n", err)
	}
	return ldsContent
}

func getPassportDataFromJson(data []byte) PassportData {
	// Implement JSON parsing logic here
	var jsonData PassportData
	err := json.Unmarshal(data, &jsonData)
	if err != nil {
		log.Fatal("Error parsing JSON data:", err)
	}
	return jsonData
}
