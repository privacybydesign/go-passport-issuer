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
	// Identifier of a completed Regula liveness transaction. The live face
	// captured during that session is compared against the document chip
	// portrait for face verification (optional).
	LivenessTransactionId string `json:"liveness_transaction_id,omitempty" example:"a1b2c3d4-5678-90ab-cdef-1234567890ab"`
	// Evidence from on-device face verification (variant B). Mutually exclusive
	// with liveness_transaction_id: a request carries one or the other (optional).
	FaceVerification *FaceVerificationEvidence `json:"face_verification,omitempty"`
}

// FaceVerificationEvidence is what the app submits after running face
// verification on the device itself (variant B, the Iris SDK). The issuer does
// not trust the client's verdict: it re-matches live_face_png against the
// document chip portrait with its own matcher before issuing.
type FaceVerificationEvidence struct {
	// Which on-device method produced the evidence. Currently only "iris".
	Method string `json:"method" example:"iris"`
	// Base64-encoded PNG of the live face crop the on-device SDK returned.
	// Request-scoped only: the issuer never stores it.
	LiveFacePng string `json:"live_face_png" example:"iVBORw0KGgo..."`
	// The verdict the SDK reported on the device ("matched"). Informational:
	// logged next to the server-side result so client/server disagreement can
	// be measured, never used to decide issuance (optional).
	ClientOutcome string `json:"client_outcome,omitempty" example:"matched"`
}
