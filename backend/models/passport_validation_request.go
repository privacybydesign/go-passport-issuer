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
	// Identifier of the Iris face session the issuer opened at verification.
	// Required at issuance when the session's assigned face verification
	// method is iris; the issuer pulls the verdict for it (optional).
	FaceSessionId string `json:"face_session_id,omitempty" example:"fs_1a2b3c"`
	// Which attempt at the face verification step this issuance follows within
	// the wallet's document flow, starting at 1. Recording only (optional).
	FaceAttempt int `json:"face_attempt,omitempty" example:"1"`
	// Milliseconds from the user confirming the face verification intro to the
	// evidence being in hand. Recording only (optional).
	FaceDurationMs int64 `json:"face_duration_ms,omitempty" example:"4200"`
}
