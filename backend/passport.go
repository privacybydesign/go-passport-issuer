package main

import "time"

type Passport struct {
	Photo                string // base64 or image URL, optional
	DocumentNumber       string
	DocumentType         string
	FirstName            string
	LastName             string
	Nationality          string
	DateOfBirth          time.Time
	DateOfExpiry         time.Time
	Gender               string // e.g., "M", "F", "X"
	Country              string // issuing country
	Over12               bool
	Over16               bool
	Over18               bool
	Over21               bool
	Over65               bool
	ActiveAuthentication bool
}
