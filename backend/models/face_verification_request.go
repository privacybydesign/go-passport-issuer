package models

type LivenessCheckRequest struct {
	TransactionId string `json:"transaction_id"`
}

type FaceMatchRequest struct {
	Image1 string `json:"image1"` // Base64 encoded image
	Image2 string `json:"image2"` // Base64 encoded image
}

type FaceDetectRequest struct {
	Image string `json:"image"` // Base64 encoded image
}
