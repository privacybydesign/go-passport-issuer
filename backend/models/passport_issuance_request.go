package models

import "time"

type PassportData struct {
	Photo                string    `json:"photo,omitempty"` // base64 or image URL, optional
	DocumentNumber       string    `json:"document_number"`
	DocumentType         string    `json:"document_type"`
	FirstName            string    `json:"first_name"`
	LastName             string    `json:"last_name"`
	Nationality          string    `json:"nationality"`
	IsEuCitizen          string    `json:"is_eu_citizen"`
	DateOfBirth          time.Time `json:"date_of_birth"`
	YearOfBirth          string    `json:"year_of_birth"`
	DateOfExpiry         time.Time `json:"date_of_expiry"`
	IssuingAuthority     string    `json:"issuing_authority"` // DG12, empty when absent
	DateOfIssue          time.Time `json:"date_of_issue"`     // DG12, zero when absent
	Gender               string    `json:"gender"`
	Country              string    `json:"country"`
	Over12               string    `json:"over12"`
	Over16               string    `json:"over16"`
	Over18               string    `json:"over18"`
	Over21               string    `json:"over21"`
	Over65               string    `json:"over65"`
	ActiveAuthentication string    `json:"active_authentication"`
}

type EDLData struct {
	Photo                string    `json:"photo,omitempty"`
	DocumentNumber       string    `json:"document_number"`
	FirstName            string    `json:"first_name"`
	LastName             string    `json:"last_name"`
	IssuingMemberState   string    `json:"issuing_member_state"`
	IssuingAuthority     string    `json:"issuing_authority"`
	DateOfBirth          time.Time `json:"date_of_birth"`
	PlaceOfBirth         string    `json:"place_of_birth"`
	YearOfBirth          string    `json:"year_of_birth"`
	DateOfExpiry         time.Time `json:"date_of_expiry"`
	Over12               string    `json:"over12"`
	Over16               string    `json:"over16"`
	Over18               string    `json:"over18"`
	Over21               string    `json:"over21"`
	Over65               string    `json:"over65"`
	ActiveAuthentication string    `json:"active_authentication"`
}
