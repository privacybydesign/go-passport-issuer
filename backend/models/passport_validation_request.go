package models

// ValidationRequest contains the document data for validation and issuance
type ValidationRequest struct {
	// Session ID obtained from /start-validation
	SessionId string `json:"session_id" example:"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"`
	// Nonce obtained from /start-validation
	Nonce string `json:"nonce" example:"1234567890abcdef"`
	// Map of data group identifiers to hex-encoded data group contents
	DataGroups map[string]string `json:"data_groups"`
	// Hex-encoded Security Object (EF.SOD) containing document signature
	EFSOD string `json:"ef_sod" example:"778201ab..."`
	// Hex-encoded active authentication signature (optional)
	ActiveAuthSignature string `json:"aa_signature,omitempty" example:"304502..."`
}
