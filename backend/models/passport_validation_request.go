package models

// IssuanceScope selects which credentials an issue request puts in the
// issuance session.
type IssuanceScope string

const (
	// IssueDocument issues only the document credential. It is the default
	// when the request names no scope.
	IssueDocument IssuanceScope = "document"
	// IssueDocumentAndAge issues the document and the age credential in the
	// same session.
	IssueDocumentAndAge IssuanceScope = "document_and_age"
	// IssueAgeOnly issues only the age credential.
	IssueAgeOnly IssuanceScope = "age_only"
)

// Valid reports whether s is a known scope. The empty scope is valid and
// means IssueDocument.
func (s IssuanceScope) Valid() bool {
	switch s {
	case "", IssueDocument, IssueDocumentAndAge, IssueAgeOnly:
		return true
	}
	return false
}

func (s IssuanceScope) IncludesDocument() bool {
	return s != IssueAgeOnly
}

func (s IssuanceScope) IncludesAge() bool {
	return s == IssueDocumentAndAge || s == IssueAgeOnly
}

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
	// Identifier of a completed Regula liveness transaction. The live face
	// captured during that session is compared against the document chip
	// portrait for face verification (optional).
	LivenessTransactionId string `json:"liveness_transaction_id,omitempty" example:"a1b2c3d4-5678-90ab-cdef-1234567890ab"`
	// Credentials to issue: "document" (default), "document_and_age" or
	// "age_only". Only used by the issue endpoints. The age credential is
	// offered only when /api/start-validation reports age_credential_offered.
	Issue IssuanceScope `json:"issue,omitempty" example:"document_and_age"`
}
