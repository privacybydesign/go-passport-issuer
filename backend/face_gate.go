package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"go-passport-issuer/analytics"
	"go-passport-issuer/models"
)

// Response bodies of the face verification gate. They reach the wallet's
// error-details dialog and support tickets verbatim.
const (
	// faceVerificationRequiredBody: the request carries no evidence for the
	// assigned method. App versions without face verification built in land
	// here once an issuer enables it, so it is self-explanatory.
	faceVerificationRequiredBody = "face verification required: this version of the app does not support face verification, please update the Yivi app to add this document"
	faceVerificationFailedBody   = "face verification failed"
	// faceAssignmentMismatchBody: evidence for a method other than the one the
	// issuer assigned. Both methods keep the verdict server-side, so this
	// protects the integrity of the recordings, not security.
	faceAssignmentMismatchBody = "face verification failed: evidence does not match the assigned method"
)

// Document types as recorded.
const (
	documentTypePassport       = "passport"
	documentTypeIdCard         = "id_card"
	documentTypeDrivingLicence = "driving_licence"
)

// faceGateInput is everything the gate needs about one issuance request.
type faceGateInput struct {
	session SessionRecord
	request models.ValidationRequest
	// portrait is the raw chip portrait (DG2/DG6 image bytes); nil when the
	// document carried none that could be extracted.
	portrait     []byte
	documentType string
}

// gateFaceVerification enforces the face verification step before issuance
// for whichever method the session was assigned, and records the outcome. It
// returns true when issuance may proceed; otherwise it has written the error
// response.
//
// When face verification is disabled for the environment the step does not
// exist and issuance proceeds. Otherwise the gate is fail-closed for every
// method: nothing softer than a verified pass gets through, since a failed
// verification withheld from the request would otherwise look like a pass.
func gateFaceVerification(state *ServerState, w http.ResponseWriter, in faceGateInput) bool {
	if !state.faceVerificationEnabled() {
		slog.Debug("Face verification disabled, skipping", "document_type", in.documentType)
		return true
	}

	method := in.session.Method
	if method == "" {
		// A session stored before assignments existed, or by an issuer version
		// running beside this one: the only method such a session can have.
		method = FaceMethodRegula
	}

	var (
		ok        bool
		outcome   string
		score     *float64
		scoreKind analytics.ScoreKind
	)
	switch method {
	case FaceMethodRegula:
		scoreKind = analytics.ScoreRegulaSimilarity
		if in.request.FaceSessionId != "" {
			respondWithErr(w, http.StatusBadRequest, faceAssignmentMismatchBody,
				"face session id on a Regula session", nil, "document_type", in.documentType)
			outcome = analytics.OutcomeAssignmentMismatch
		} else {
			ok, outcome, score = regulaGate(state, w, portraitBase64(in.portrait), in.request.LivenessTransactionId, in.documentType)
		}
	case FaceMethodIris:
		scoreKind = analytics.ScoreIrisDistance
		if in.request.LivenessTransactionId != "" {
			respondWithErr(w, http.StatusBadRequest, faceAssignmentMismatchBody,
				"liveness transaction id on an Iris session", nil, "document_type", in.documentType)
			outcome = analytics.OutcomeAssignmentMismatch
		} else {
			ok, outcome, score = irisGate(state, w, in)
		}
	default:
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal,
			"session assigned an unknown face verification method", fmt.Errorf("method %q", method))
		outcome = analytics.OutcomeError
	}

	event := analytics.Record{
		Kind:         analytics.KindIssuance,
		Method:       method,
		Client:       in.session.Client,
		DocumentType: in.documentType,
		AttemptKind:  in.session.attemptKind(),
		Outcome:      outcome,
		Score:        score,
	}
	if score != nil {
		event.ScoreKind = scoreKind
	}
	if in.request.FaceDurationMs > 0 {
		event.DurationMs = analytics.Int64(in.request.FaceDurationMs)
	}
	if in.request.FaceAttempt > 1 {
		// The wallet's own count wins over what it declared at session start:
		// it is the one that ran the attempts.
		event.AttemptKind = analytics.AttemptRetry
	}
	state.record(context.Background(), event)
	return ok
}

func portraitBase64(portrait []byte) string {
	if len(portrait) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(portrait)
}

// regulaGate is verifyFaceBeforeIssuance with its outcome made visible for the
// recordings. It writes the error response itself when it refuses.
func regulaGate(state *ServerState, w http.ResponseWriter, documentImage, livenessTransactionID, documentType string) (bool, string, *float64) {
	if livenessTransactionID == "" {
		slog.Warn("Liveness transaction required for issuance", "document_type", documentType)
		respondWithErr(w, http.StatusBadRequest, faceVerificationRequiredBody,
			"no liveness transaction provided for issuance", nil, "document_type", documentType)
		return false, analytics.OutcomeEvidenceMissing, nil
	}

	slog.Info("Performing face verification before issuance", "document_type", documentType)
	faceMatch, err := performFaceMatch(state, documentImage, livenessTransactionID)
	if err != nil {
		slog.Warn("Face verification failed during issuance", "document_type", documentType, "error", err)
		respondWithErr(w, http.StatusBadRequest, faceVerificationFailedBody, "face verification error during issuance", err, "document_type", documentType)
		if strings.Contains(err.Error(), "liveness not confirmed") {
			return false, analytics.OutcomeLivenessRejected, nil
		}
		return false, analytics.OutcomeError, nil
	}

	if faceMatch == nil || !faceMatch.Matched {
		similarity := 0.0
		if faceMatch != nil {
			similarity = faceMatch.Score
		}
		slog.Warn("Face verification failed - similarity below threshold", "similarity", similarity)
		respondWithErr(w, http.StatusBadRequest, faceVerificationFailedBody, "face does not match document photo", fmt.Errorf("similarity: %f", similarity))
		return false, analytics.OutcomeMatchRejected, analytics.Float64(similarity)
	}

	slog.Debug("Face verification passed", "similarity", faceMatch.Score)
	return true, analytics.OutcomePassed, analytics.Float64(faceMatch.Score)
}

// irisGate checks an Iris session's evidence: a face record that belongs to
// this document session and was opened for this very portrait, and a completed
// session whose distance passes this issuer's threshold. The verifier's own
// verdict is not what decides; the client applies the configured threshold to
// the distance, as the Regula path does to a similarity. On success it deletes
// the verifier session and the face record; nothing about the attempt outlives
// the issuance.
func irisGate(state *ServerState, w http.ResponseWriter, in faceGateInput) (bool, string, *float64) {
	documentType := in.documentType
	faceSessionID := in.request.FaceSessionId
	if faceSessionID == "" {
		slog.Warn("Face session required for issuance", "document_type", documentType)
		respondWithErr(w, http.StatusBadRequest, faceVerificationRequiredBody,
			"no face session provided for issuance", nil, "document_type", documentType)
		return false, analytics.OutcomeEvidenceMissing, nil
	}
	if state.irisClient == nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal,
			"iris session assigned without an iris client", nil, "document_type", documentType)
		return false, analytics.OutcomeError, nil
	}

	rec, err := retrieveFaceRecord(state.tokenStorage, faceSessionID)
	if err != nil {
		respondWithErr(w, http.StatusBadRequest, faceVerificationFailedBody,
			"unknown face session", err, "document_type", documentType, "face_session_id", faceSessionID)
		return false, analytics.OutcomeEvidenceMissing, nil
	}
	if rec.SessionID != in.request.SessionId {
		respondWithErr(w, http.StatusBadRequest, faceVerificationFailedBody,
			"face session belongs to another document session", nil, "document_type", documentType, "face_session_id", faceSessionID)
		return false, analytics.OutcomeEvidenceMissing, nil
	}
	if len(in.portrait) == 0 || portraitSha256Hex(in.portrait) != rec.PortraitSha256 {
		// The face session was opened for a different portrait than the one
		// being issued now: a verdict is only ever good for the document it
		// was obtained against.
		respondWithErr(w, http.StatusBadRequest, faceVerificationFailedBody,
			"portrait does not match the face session", nil, "document_type", documentType, "face_session_id", faceSessionID)
		return false, analytics.OutcomeAssignmentMismatch, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	status, err := state.irisClient.GetSession(ctx, faceSessionID)
	if err != nil {
		respondWithErr(w, http.StatusBadRequest, faceVerificationFailedBody,
			"failed to retrieve iris verdict", err, "document_type", documentType, "face_session_id", faceSessionID)
		return false, analytics.OutcomeError, nil
	}

	var score *float64
	if status.Match != nil {
		score = analytics.Float64(status.Match.Score)
	}
	switch {
	case status.Status == irisStatusCompleted && status.Match != nil && status.Match.Matched:
		// The verdict has served its purpose; the verifier keeps nothing.
		if err := state.irisClient.DeleteSession(ctx, faceSessionID); err != nil {
			slog.Warn("Failed to delete iris session", "error", err, "face_session_id", faceSessionID)
		}
		if err := deleteFaceRecord(state.tokenStorage, faceSessionID); err != nil {
			slog.Warn("Failed to delete face record", "error", err, "face_session_id", faceSessionID)
		}
		slog.Debug("Face verification passed", "distance", status.Match.Score)
		return true, analytics.OutcomePassed, score
	case status.Status == irisStatusCompleted:
		// A completed session always carries a distance, so Match is set; the
		// zero value would only surface if the verifier broke that contract.
		distance := 0.0
		if status.Match != nil {
			distance = status.Match.Score
		}
		respondWithErr(w, http.StatusBadRequest, faceVerificationFailedBody,
			"face does not match document photo", fmt.Errorf("distance: %f", distance), "document_type", documentType)
		return false, analytics.OutcomeMatchRejected, score
	case status.Status == irisStatusFailed:
		// The engine judged the frame sequence not live, or found no face it
		// could compare: Iris does not separate the two.
		respondWithErr(w, http.StatusBadRequest, faceVerificationFailedBody,
			"iris verifier failed the session", nil, "document_type", documentType)
		return false, analytics.OutcomeLivenessRejected, score
	default:
		respondWithErr(w, http.StatusBadRequest, faceVerificationFailedBody,
			"iris session not completed", fmt.Errorf("status: %s", status.Status), "document_type", documentType)
		return false, analytics.OutcomeEvidenceMissing, score
	}
}

// FaceSessionAnnouncement is the `face_session` object a verify response
// carries when the session's method is Iris: what the wallet needs to stream
// its frames.
type FaceSessionAnnouncement struct {
	FaceSessionId string `json:"face_session_id" example:"fs_1a2b3c"`
	// WebSocket endpoint of the verifier's stream for this session
	StreamUrl string `json:"stream_url" example:"wss://iris-verifier.staging.yivi.app/stream/fs_1a2b3c"`
	// Presented by the wallet as the first message on the stream
	Token string `json:"token"`
	// Seconds until the session expires when streaming has not started
	ExpiresIn int `json:"expires_in" example:"600"`
}

// openIrisFaceSession opens a verifier session for the authenticated portrait,
// records the binding to the document session, and returns what the wallet
// needs. Called by the verify handlers when the session's method is Iris.
func openIrisFaceSession(ctx context.Context, state *ServerState, sessionId string, portrait []byte, documentType string) (*FaceSessionAnnouncement, error) {
	if state.irisClient == nil {
		return nil, fmt.Errorf("iris verifier client not configured")
	}
	if len(portrait) == 0 {
		return nil, fmt.Errorf("document carries no portrait")
	}
	hash := portraitSha256Hex(portrait)
	session, err := state.irisClient.CreateSession(ctx, portraitBase64(portrait), hash, documentType)
	if err != nil {
		return nil, fmt.Errorf("failed to open iris face session: %w", err)
	}
	if err := storeFaceRecord(state.tokenStorage, FaceRecord{
		FaceSessionID:  session.FaceSessionID,
		SessionID:      sessionId,
		PortraitSha256: hash,
		DocumentType:   documentType,
		CreatedAt:      time.Now(),
	}); err != nil {
		return nil, fmt.Errorf("failed to store face record: %w", err)
	}
	expiresIn := 600
	if !session.ExpiresAt.IsZero() {
		if remaining := int(time.Until(session.ExpiresAt).Seconds()); remaining >= 0 {
			expiresIn = remaining
		}
	}
	return &FaceSessionAnnouncement{
		FaceSessionId: session.FaceSessionID,
		StreamUrl:     strings.TrimRight(state.irisVerifierPublicUrl, "/") + "/stream/" + session.FaceSessionID,
		Token:         session.Token,
		ExpiresIn:     expiresIn,
	}, nil
}
