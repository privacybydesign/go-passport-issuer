package main

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"log"
	"os"
	"time"
)

// Main ContentInfo structure
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// SignedData structure
type SignedData struct {
	Version                 int
	DigestAlgorithms        []DigestAlgorithmIdentifier `asn1:"set"`
	EncapsulatedContentInfo EncapsulatedContentInfo
	Certificates            []asn1.RawValue `asn1:"implicit,optional,tag:0,set"`
	CRLs                    []asn1.RawValue `asn1:"implicit,optional,tag:1,set"`
	SignerInfos             []SignerInfo    `asn1:"set"`
}

// DigestAlgorithmIdentifier structure
type DigestAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// EncapsulatedContentInfo structure
type EncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,optional,tag:0"`
}

// SignerInfo structure
type SignerInfo struct {
	Version            int
	SignerIdentifier   asn1.RawValue
	DigestAlgorithm    DigestAlgorithmIdentifier
	SignedAttrs        []Attribute `asn1:"implicit,optional,tag:0,set"`
	SignatureAlgorithm DigestAlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      []Attribute `asn1:"implicit,optional,tag:1,set"`
}

// Attribute structure
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// MasterList represents the complete master list structure
// The eContent directly contains a SEQUENCE with version and certificate set
type MasterList struct {
	Version        int
	CertificateSet []Entry `asn1:"set"`
}

type Entry struct {
	Certificate asn1.RawValue             // full DER-encoded certificate
	OID         DigestAlgorithmIdentifier // second element
	Signature   asn1.BitString            // third element
}

// CertificateEntry represents a parsed certificate entry
type CertificateEntry struct {
	CountryName      string
	OrganizationName string
	CommonName       string
	SerialNumber     string
	ValidFrom        time.Time
	ValidTo          time.Time
}

func main() {
	// Read the DER file
	if len(os.Args) != 2 {
		log.Fatal("Usage: extract_dg_hashes NL_MASTERLIST.mls")
	}

	masterlistFileName := os.Args[1]
	rawData, err := os.ReadFile(masterlistFileName)
	if err != nil {
		log.Fatal("Error reading file:", err)
	}

	// Parse the master list
	masterList, err := parseMasterList(rawData)
	if err != nil {
		log.Fatalf("Failed to parse master list: %v", err)
	}

	// Display results
	fmt.Printf("Successfully parsed master list with version %d and %d certificate entries\n", masterList.Version, len(masterList.CertificateSet))

	// Example: Print first few certificate raw data lengths
	for i, entry := range masterList.CertificateSet {
		if i >= 5 { // Only show first 5 entries
			break
		}
		fmt.Printf("Certificate %d raw data length: %d bytes\n", i+1, len(entry.Certificate.Bytes))
		fmt.Printf("Certificate %d OID: %s\n", i+1, entry.OID.Algorithm.String())

		var result interface{}
		_, err = asn1.Unmarshal(entry.Certificate.FullBytes, &result)
		if err != nil {
			fmt.Println("Failed to unmarshal:", err)
			return
		}

		fmt.Printf("Parsed result: %+v\n", result)

		cert, err := entry.ToX509Certificate()
		if err != nil {
			fmt.Printf("Failed to parse certificate %d: %v\n", i, err)
			continue
		}
		// fmt.Printf("Certificate %d:\n", i+1)
		// fmt.Printf("  Subject: %s\n", cert.Subject.String())
		// fmt.Printf("  Issuer:  %s\n", cert.Issuer.String())
		// fmt.Printf("  Valid From: %s\n", cert.NotBefore)
		fmt.Printf("  Valid To:   %s\n", cert.NotAfter)

	}
}

func (e *Entry) ToX509Certificate() (*x509.Certificate, error) {
	return x509.ParseCertificate(e.Certificate.Bytes)
}

func parseMasterList(derData []byte) (*MasterList, error) {
	// First, parse the outer ContentInfo structure
	var contentInfo ContentInfo
	_, err := asn1.Unmarshal(derData, &contentInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ContentInfo: %v", err)
	}

	// Parse the SignedData from the Content RawValue
	var signedData SignedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SignedData: %v", err)
	}

	// Extract the eContent from EncapsulatedContentInfo
	eContent := signedData.EncapsulatedContentInfo.EContent
	if len(eContent) == 0 {
		return nil, fmt.Errorf("no eContent found in EncapsulatedContentInfo")
	}

	// The eContent directly contains the master list data as a SEQUENCE
	// Parse the master list from eContent (no OCTET STRING wrapper)
	var masterList MasterList
	_, err = asn1.Unmarshal(eContent, &masterList)
	if err != nil {
		return nil, fmt.Errorf("failed to parse master list: %v", err)
	}

	return &masterList, nil
}
