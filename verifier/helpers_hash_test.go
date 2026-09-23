package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
