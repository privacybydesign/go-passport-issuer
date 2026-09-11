package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"
	"log/slog"
	"net/http"

	"go-passport-issuer/models"
)

// Face verification method identifiers, as announced to the app in
// /api/start-validation and as submitted back in FaceVerificationEvidence.
const (
	// FaceVerificationMethodRegula is variant A: a Regula liveness session
	// referenced by transaction id, matched server-side by Regula.
	FaceVerificationMethodRegula = "regula"
	// FaceVerificationMethodIris is variant B: the on-device Iris SDK. The app
	// submits the live face crop and the issuer re-matches it with its own
	// (Regula-free) FaceMatcher.
	FaceVerificationMethodIris = "iris"
)

// Bounds on the live face crop an app may submit. The Iris SDK returns a
// tight crop, so anything far outside these limits is not a crop from the SDK.
const (
	// maxLiveFaceBytes caps the decoded PNG size (2 MiB).
	maxLiveFaceBytes = 2 << 20
	// minLiveFaceDimension is the smallest usable width/height in pixels; an
	// ArcFace model is fed 112x112 aligned faces, so a smaller crop only
	// degrades the match.
	minLiveFaceDimension = 64
	// maxLiveFaceDimension bounds the work the matcher's detector has to do.
	maxLiveFaceDimension = 4096
)

// faceEvidence is what a request carries for face verification, in whichever
// form the variant the app ran produces. At most one of the two is set.
type faceEvidence struct {
	// LivenessTransactionID is variant A's evidence.
	LivenessTransactionID string
	// OnDevice is variant B's evidence.
	OnDevice *models.FaceVerificationEvidence
}

// faceEvidenceFrom extracts the face verification evidence from a request.
func faceEvidenceFrom(request *models.ValidationRequest) faceEvidence {
	return faceEvidence{
		LivenessTransactionID: request.LivenessTransactionId,
		OnDevice:              request.FaceVerification,
	}
}

// mixed reports whether the request carries evidence for both variants. A
// client never legitimately runs both; the issuer refuses to pick one for it.
func (e faceEvidence) mixed() bool {
	return e.LivenessTransactionID != "" && e.OnDevice != nil
}

// decodeLiveFacePng validates and decodes the base64 PNG an app submits as
// variant B evidence. It checks the encoding, the size cap and that the bytes
// are a real PNG of plausible dimensions, using only the image header so no
// pixel buffer is allocated for a hostile input. It does not detect faces;
// that is the matcher's job.
func decodeLiveFacePng(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, fmt.Errorf("live_face_png is required")
	}
	// Reject early on the encoded length so we never allocate the decoded
	// buffer for an oversized input. Base64 expands by 4/3.
	if base64.StdEncoding.DecodedLen(len(encoded)) > maxLiveFaceBytes {
		return nil, fmt.Errorf("live_face_png exceeds %d bytes", maxLiveFaceBytes)
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("live_face_png is not valid base64: %w", err)
	}
	if len(data) > maxLiveFaceBytes {
		return nil, fmt.Errorf("live_face_png exceeds %d bytes", maxLiveFaceBytes)
	}

	cfg, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("live_face_png is not a PNG image: %w", err)
	}
	if cfg.Width < minLiveFaceDimension || cfg.Height < minLiveFaceDimension {
		return nil, fmt.Errorf("live_face_png is too small (%dx%d, minimum %d)", cfg.Width, cfg.Height, minLiveFaceDimension)
	}
	if cfg.Width > maxLiveFaceDimension || cfg.Height > maxLiveFaceDimension {
		return nil, fmt.Errorf("live_face_png is too large (%dx%d, maximum %d)", cfg.Width, cfg.Height, maxLiveFaceDimension)
	}

	return data, nil
}

// performOnDeviceFaceMatch is the server-side half of variant B. The app ran
// liveness and matching on the device; the issuer independently re-matches
// the live face crop it returned against the document chip portrait with the
// configured FaceMatcher. Nothing here calls Regula.
//
// The crop lives only for the duration of this call. It is not written to
// storage or to the log.
func performOnDeviceFaceMatch(state *ServerState, documentImageBase64 string, evidence *models.FaceVerificationEvidence) (*FaceMatchResult, error) {
	slog.Debug("Starting on-device face match verification")

	if state.faceMatcher == nil {
		return nil, fmt.Errorf("face matcher not configured")
	}
	if evidence == nil {
		return nil, fmt.Errorf("no on-device face verification evidence provided")
	}
	if evidence.Method != FaceVerificationMethodIris {
		return nil, fmt.Errorf("unsupported on-device face verification method %q", evidence.Method)
	}
	if documentImageBase64 == "" {
		return nil, fmt.Errorf("document photo not available")
	}

	documentImage, err := base64.StdEncoding.DecodeString(documentImageBase64)
	if err != nil {
		return nil, fmt.Errorf("document photo is not valid base64: %w", err)
	}

	liveFace, err := decodeLiveFacePng(evidence.LiveFacePng)
	if err != nil {
		return nil, err
	}

	response, err := state.faceMatcher.MatchImages(documentImage, liveFace)
	if err != nil {
		return nil, fmt.Errorf("face matching failed: %w", err)
	}

	// The client's own verdict is recorded next to ours purely so the
	// disagreement rate can be measured for the experiment.
	slog.Info("On-device face match verified server-side",
		"method", evidence.Method,
		"matched", response.Matched,
		"similarity", response.Similarity,
		"client_outcome", evidence.ClientOutcome,
		"disagreement", evidence.ClientOutcome != "" && (evidence.ClientOutcome == "matched") != response.Matched)

	return &FaceMatchResult{
		Matched:    response.Matched,
		Similarity: response.Similarity,
		Method:     evidence.Method,
	}, nil
}

// verifyOnDeviceFaceBeforeIssuance enforces variant B before issuance and
// returns true when issuance may proceed. Fail-closed like variant A: any
// error, and any similarity below the threshold, rejects the request.
func verifyOnDeviceFaceBeforeIssuance(state *ServerState, w http.ResponseWriter, documentImage string, evidence *models.FaceVerificationEvidence, documentType string) bool {
	if state.faceMatcher == nil {
		slog.Warn("On-device face verification submitted but no face matcher configured", "document_type", documentType)
		respondWithErr(w, http.StatusBadRequest,
			"face verification failed: on-device face verification is not supported by this issuer",
			"on-device face verification evidence without a configured face matcher", nil,
			"document_type", documentType)
		return false
	}

	slog.Info("Performing on-device face verification before issuance", "document_type", documentType, "method", evidence.Method)
	faceMatch, err := performOnDeviceFaceMatch(state, documentImage, evidence)
	if err != nil {
		slog.Warn("On-device face verification failed during issuance", "document_type", documentType, "error", err)
		respondWithErr(w, http.StatusBadRequest, "face verification failed", "on-device face verification error during issuance", err, "document_type", documentType)
		return false
	}

	if !faceMatch.Matched {
		slog.Warn("On-device face verification failed - similarity below threshold", "similarity", faceMatch.Similarity)
		respondWithErr(w, http.StatusBadRequest, "face verification failed", "face does not match document photo", fmt.Errorf("similarity: %f", faceMatch.Similarity))
		return false
	}

	slog.Debug("On-device face verification passed", "similarity", faceMatch.Similarity)
	return true
}
