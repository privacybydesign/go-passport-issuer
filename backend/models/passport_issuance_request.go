package models

import "time"

type PassportIssuanceRequest struct {
	Photo                string    `json:"photo,omitempty"` // base64 or image URL, optional
	DocumentNumber       string    `json:"document_number"`
	DocumentType         string    `json:"document_type"`
	FirstName            string    `json:"first_name"`
	LastName             string    `json:"last_name"`
	Nationality          string    `json:"nationality"`
	DateOfBirth          time.Time `json:"date_of_birth"`
	DateOfExpiry         time.Time `json:"date_of_expiry"`
	Gender               string    `json:"gender"`
	Country              string    `json:"country"`
	Over12               string    `json:"over12"`
	Over16               string    `json:"over16"`
	Over18               string    `json:"over18"`
	Over21               string    `json:"over21"`
	Over65               string    `json:"over65"`
	ActiveAuthentication string    `json:"active_authentication"`
}
