package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// faceRecordPrefix namespaces face records inside the shared TokenStorage,
// apart from the document session records.
const faceRecordPrefix = "facerec:"

// FaceRecord binds an Iris face session to the document session it was opened
// for and to the portrait it was opened with. The issuer writes it when the
// verify step opens the face session and checks it at issuance: the issuance
// request must carry the same portrait, so a verdict obtained against one
// document can never issue another. The record holds a hash, never the
// portrait.
type FaceRecord struct {
	FaceSessionID  string    `json:"face_session_id"`
	SessionID      string    `json:"session_id"`
	PortraitSha256 string    `json:"portrait_sha256"`
	DocumentType   string    `json:"document_type"`
	CreatedAt      time.Time `json:"created_at"`
}

func faceRecordKey(faceSessionID string) string {
	return faceRecordPrefix + faceSessionID
}

func storeFaceRecord(storage TokenStorage, rec FaceRecord) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("failed to marshal face record: %w", err)
	}
	return storage.StoreToken(faceRecordKey(rec.FaceSessionID), string(b))
}

func retrieveFaceRecord(storage TokenStorage, faceSessionID string) (FaceRecord, error) {
	raw, err := storage.RetrieveToken(faceRecordKey(faceSessionID))
	if err != nil {
		return FaceRecord{}, err
	}
	var rec FaceRecord
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		return FaceRecord{}, fmt.Errorf("failed to unmarshal face record: %w", err)
	}
	return rec, nil
}

func deleteFaceRecord(storage TokenStorage, faceSessionID string) error {
	return storage.RemoveToken(faceRecordKey(faceSessionID))
}

// portraitSha256Hex hashes the raw portrait image bytes as read from the chip
// (DG2 for passports and ID cards, DG6 for driving licences), hex-encoded.
// The same bytes are what the verifier receives as the portrait.
func portraitSha256Hex(portrait []byte) string {
	sum := sha256.Sum256(portrait)
	return hex.EncodeToString(sum[:])
}
