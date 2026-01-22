package models

type ValidationRequest struct {
	SessionId           string            `json:"session_id"`
	Nonce               string            `json:"nonce"`
	DataGroups          map[string]string `json:"data_groups"`
	EFSOD               string            `json:"ef_sod"`
	ActiveAuthSignature string            `json:"aa_signature,omitempty"`
	SelfieImage         string            `json:"selfie_image,omitempty"` // Base64 encoded selfie for face verification
}
