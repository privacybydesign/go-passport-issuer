package main

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-ldap/ldif"
)

func main() {
	args := os.Args[1:]

	if len(args) < 1 {
		log.Fatal("Usage: go run main.go <file-path>")
	}

	filePath := args[0]
	ext := strings.ToLower(filepath.Ext(filePath))

	if ext != ".ldif" && ext != ".mls" {
		log.Fatal("Please provide a valid LDIF or MLS file.")
	}

	switch ext {
	case ".ldif":
		err := readLdifFile(filePath)
		if err != nil {
			log.Fatalf("Error reading LDIF file: %v", err)
		}

	case ".mls":
		err := readMLSFile(filePath)
		if err != nil {
			log.Fatalf("Error reading MLS file: %v", err)
		}
	}
}

func readLdifFile(filePath string) error {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	// Read the entire file into memory
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	// Parse the LDIF
	content := string(data)
	parsedLDIF, err := ldif.Parse(content)
	if err != nil {
		fmt.Printf("Error parsing LDIF: %v\n", err)
		return err
	}

	// Loop through each entry
	fmt.Printf("Parsed %d entries from LDIF file:\n", len(parsedLDIF.Entries))
	certificates := 0
	for _, entry := range parsedLDIF.Entries[:100] {
		if entry != nil && entry.Entry != nil {
			fmt.Printf("DN: %s\n", entry.Entry.DN)
			if entry.Entry.Attributes != nil {
				for _, attr := range entry.Entry.Attributes {
					if attr.Name == "userCertificate;binary" {
						// Process the binary certificate
						certData := attr.ByteValues[0]
						// Decode the certificate
						cert, err := x509.ParseCertificate(certData)
						if err != nil {
							fmt.Printf("Error parsing certificate: %v\n", err)
							continue
						}
						// Dumpt certificate to file
						certFileName := fmt.Sprintf("certs/cert_%s.cer", cert.SerialNumber.String())
						err = os.WriteFile(certFileName, cert.Raw, 0644)
						if err != nil {
							fmt.Printf("Error writing certificate to file: %v\n", err)
							continue
						}
						certificates++
					}
				}
			}
		}
	}
	fmt.Printf("Total userCertificate;binary found: %d\n", certificates)

	return nil
}

func readMLSFile(filePath string) error {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	// Read binary file
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		os.Exit(1)
	}

	// Step 1: Unmarshal the outer ContentInfo
	var contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
	}
	_, err = asn1.Unmarshal(data, &contentInfo)
	if err != nil {
		log.Fatalf("Failed to unmarshal ContentInfo: %v", err)
	}

	fmt.Println("Content Type OID:", contentInfo.ContentType.String())
	// Should be 1.2.840.113549.1.7.2 for SignedData

	// Step 2: Unwrap SignedData (this is a SEQUENCE)
	var signedData asn1.RawValue
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &signedData)
	if err != nil {
		log.Fatalf("Failed to unwrap SignedData: %v", err)
	}

	// Step 3: Manually extract certificate section (tagged [0])
	var signedSeq []asn1.RawValue
	_, err = asn1.Unmarshal(signedData.FullBytes, &signedSeq)
	if err != nil {
		log.Fatalf("Failed to parse SignedData sequence: %v", err)
	}

	// Step 4: Find and decode [0] IMPLICIT CertificateSet
	for _, el := range signedSeq {
		if el.Class == 2 && el.Tag == 0 { // [0] tagged
			fmt.Println("Found certificate set (tag [0])")

			// Step 5: Decode SET OF CertificateChoices
			var certChoices []asn1.RawValue
			_, err := asn1.Unmarshal(el.Bytes, &certChoices)
			if err != nil {
				log.Fatalf("Failed to unmarshal certificate set: %v", err)
			}

			for i, certChoice := range certChoices {
				if certChoice.Class == 0 { // UNIVERSAL
					// Could be directly a certificate (unlikely in CertificateChoices, but let's check)
					cert, err := x509.ParseCertificate(certChoice.FullBytes)
					if err != nil {
						log.Printf("Skipping malformed cert %d (universal): %v", i+1, err)
						continue
					}
					printCertInfo(i+1, cert)
				} else if certChoice.Class == 2 && certChoice.Tag == 0 {
					// Context-specific [0], probably a regular X.509 cert
					cert, err := x509.ParseCertificate(certChoice.Bytes) // Use Bytes, not FullBytes
					if err != nil {
						log.Printf("Skipping malformed cert %d (context-specific): %v", i+1, err)
						continue
					}
					printCertInfo(i+1, cert)
				} else {
					log.Printf("Skipping unsupported cert type %d (class=%d tag=%d)", i+1, certChoice.Class, certChoice.Tag)
				}
			}
		}
	}
	return nil
}

func printCertInfo(i int, cert *x509.Certificate) {
	fmt.Printf("Certificate %d:\n", i)
	fmt.Printf("  Subject: %s\n", cert.Subject)
	fmt.Printf("  Issuer: %s\n", cert.Issuer)
	fmt.Printf("  Valid: %s to %s\n", cert.NotBefore, cert.NotAfter)
	fmt.Printf("  Serial: %s\n", cert.SerialNumber)
}
