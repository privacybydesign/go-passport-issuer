package models

type LivenessCheckResponse struct {
	TransactionId string  `json:"transaction_id"`
	Liveness      int     `json:"liveness"`      // 0 = confirmed, 1 = not confirmed
	Status        int     `json:"status"`        // Status code from Regula API
	Similarity    float64 `json:"similarity"`    // Similarity score if face matching was performed
	Tag           string  `json:"tag,omitempty"` // Optional tag for session
}

type FaceMatchResponse struct {
	Similarity float64                    `json:"similarity"` // 0-1 similarity score
	Matched    bool                       `json:"matched"`    // Whether faces match based on threshold
	DetectedFaces []DetectedFace          `json:"detected_faces,omitempty"`
}

type FaceDetectResponse struct {
	DetectedFaces []DetectedFace `json:"detected_faces"`
}

type DetectedFace struct {
	Quality       float64         `json:"quality"`       // Image quality score
	Crop          string          `json:"crop"`          // Base64 encoded cropped face
	Attributes    *FaceAttributes `json:"attributes,omitempty"`
}

type FaceAttributes struct {
	Age     int    `json:"age,omitempty"`
	Gender  string `json:"gender,omitempty"`
	Glasses bool   `json:"glasses,omitempty"`
}
