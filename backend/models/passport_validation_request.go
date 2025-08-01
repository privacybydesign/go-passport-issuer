package models

type PassportValidationRequest struct {
	SessionId  string            `json:"session_id"`
	Nonce      string            `json:"nonce"`
	DataGroups map[string]string `json:"data_groups"`
	EFSOD      string            `json:"EF_SOD"`
}
