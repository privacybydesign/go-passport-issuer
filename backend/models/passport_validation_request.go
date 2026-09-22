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
	// Verdict of the Iris SDK that ran on the device: whether the live face it
	// captured matched the document chip portrait. Required at issuance when
	// the session's assigned method is iris_ondevice. A pointer so that an
	// absent field (the step was never run) stays distinguishable from false
	// (it ran and the face was rejected) — the two are answered differently.
	// The issuer cannot check this value; it is the client's word (optional).
	FaceOndevicePassed *bool `json:"face_ondevice_passed,omitempty" example:"true"`
	// SHA-256, hex, of the portrait bytes the on-device SDK matched against.
	// Compared with the portrait this request is being issued for, so a
	// passing verdict cannot be carried over to another document (optional).
	FaceOndevicePortraitSha256 string `json:"face_ondevice_portrait_sha256,omitempty" example:"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"`
	// Which attempt at the face verification step this issuance follows within
	// the wallet's document flow, starting at 1. Recording only (optional).
	FaceAttempt int `json:"face_attempt,omitempty" example:"1"`
	// Milliseconds from the user confirming the face verification intro to the
	// evidence being in hand. Recording only (optional).
	FaceDurationMs int64 `json:"face_duration_ms,omitempty" example:"4200"`
}
