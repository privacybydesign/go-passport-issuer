package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go-passport-issuer/models"
	"io"
	"log/slog"
	"net/http"
)

// Face verification result statuses.
const (
	faceStatusPending = "pending"
	faceStatusSuccess = "success"
)

// faceRecordPrefix namespaces the face verification records inside the shared
// TokenStorage, keeping them separate from validation-session nonces.
const faceRecordPrefix = "facerec:"

// faceGateBodyRequired and friends are returned verbatim to the client so it can
// branch on the reason a gated issuance was refused.
const (
	faceGateRequired = "face:required"
	faceGateFailed   = "face:failed"
	faceGateMismatch = "face:mismatch"
	faceGatePending  = "face:pending"
)

// FaceRecord is the issuer-side state for one face verification session. It is
// created (status "pending") when verify-passport starts the session and updated
// to the terminal verdict by the signed callback (or the status poll). The
// binding_secret authenticates the callback and is never returned to the wallet.
type FaceRecord struct {
	FaceSessionID   string   `json:"face_session_id"`
	SessionID       string   `json:"session_id"`
	BindingSecret   string   `json:"binding_secret"`
	Dg2Sha256       string   `json:"dg2_sha256"`
	Status          string   `json:"status"`
	MatchConfidence *float64 `json:"match_confidence,omitempty"`
	LivenessPassed  *bool    `json:"liveness_passed,omitempty"`
}

func faceRecordKey(faceSessionID string) string {
	return faceRecordPrefix + faceSessionID
}

func storeFaceRecord(storage TokenStorage, rec *FaceRecord) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("failed to marshal face record: %w", err)
	}
	return storage.StoreToken(faceRecordKey(rec.FaceSessionID), string(b))
}

func retrieveFaceRecord(storage TokenStorage, faceSessionID string) (*FaceRecord, error) {
	raw, err := storage.RetrieveToken(faceRecordKey(faceSessionID))
	if err != nil {
		return nil, err
	}
	var rec FaceRecord
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		return nil, fmt.Errorf("failed to unmarshal face record: %w", err)
	}
	return &rec, nil
}

// portraitDataGroups lists the data-group keys that carry a face portrait, in
// priority order: DG2 for eMRTD passports/ID cards, DG6 for ISO-18013 eDLs.
var portraitDataGroups = []string{"DG2", "DG6"}

// portraitRawBytes returns the raw bytes of the document's face portrait data
// group (DG2 for passports/ID cards, DG6 for driving licences), if present.
func portraitRawBytes(dataGroups map[string]string) ([]byte, bool) {
	for _, key := range portraitDataGroups {
		h := dataGroups[key]
		if h == "" {
			continue
		}
		raw, err := hex.DecodeString(h)
		if err != nil {
			continue
		}
		return raw, true
	}
	return nil, false
}

// portraitSha256Hex returns SHA256 of the raw portrait bytes (hex-encoded),
// matching the face service's reference-photo salt: the issuer sends
// base64(raw portrait DG) as the portrait, and the service hashes the decoded
// bytes for binding. Returns "" when the document carries no portrait DG.
func portraitSha256Hex(dataGroups map[string]string) string {
	raw, ok := portraitRawBytes(dataGroups)
	if !ok {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// canonicalJSON reproduces Python's
// json.dumps(obj, sort_keys=True, separators=(",", ":")) byte-for-byte for the
// callback payload: Go marshals maps with sorted keys and compact separators;
// HTML escaping is disabled and the trailing newline trimmed. Numbers are
// preserved verbatim via json.Number so integral floats (e.g. 1.0) are not
// rewritten as 1.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// FaceCallbackResponse is returned to the face verification service.
type FaceCallbackResponse struct {
	Ok bool `json:"ok"`
}

// handleFaceCallback receives the signed verification result from the face
// verification service. The payload signature is an HMAC-SHA256 (hex) of the
// canonical JSON of the body without its "signature" field, keyed by the
// session's binding_secret.
//
// @Summary Face verification result callback
// @Description Server-to-server webhook called by the face verification service with the signed result of a session.
// @Tags Face
// @Accept json
// @Produce json
// @Success 200 {object} FaceCallbackResponse
// @Failure 400 {string} string "invalid request"
// @Failure 401 {string} string "invalid signature"
// @Failure 404 {string} string "unknown session"
// @Router /face/callback [post]
func handleFaceCallback(state *ServerState, w http.ResponseWriter, r *http.Request) {
	defer closeRequestBody(r)

	if !requirePOST(w, r) {
		return
	}

	const endpoint = "face/callback"

	body, err := readLimitedBody(r)
	if err != nil {
		respondWithErr(w, http.StatusBadRequest, "invalid request", "failed to read callback body", err, "endpoint", endpoint)
		return
	}

	// Decode preserving number literals so the signature recomputation matches
	// the sender's canonical JSON exactly.
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var payload map[string]any
	if err := dec.Decode(&payload); err != nil {
		respondWithErr(w, http.StatusBadRequest, "invalid request", "failed to decode callback body", err, "endpoint", endpoint)
		return
	}

	faceSessionID, _ := payload["face_session_id"].(string)
	if faceSessionID == "" {
		respondWithErr(w, http.StatusBadRequest, "invalid request", "callback missing face_session_id", fmt.Errorf("missing face_session_id"), "endpoint", endpoint)
		return
	}

	rec, err := retrieveFaceRecord(state.tokenStorage, faceSessionID)
	if err != nil {
		respondWithErr(w, http.StatusNotFound, "unknown session", "callback for unknown face session", err,
			"endpoint", endpoint, "face_session_id", faceSessionID)
		return
	}

	if !verifyCallbackSignature(payload, rec.BindingSecret) {
		respondWithErr(w, http.StatusUnauthorized, "invalid signature", "callback signature mismatch", fmt.Errorf("hmac mismatch"),
			"endpoint", endpoint, "face_session_id", faceSessionID)
		return
	}

	// Signature verified — record the verdict.
	result, _ := payload["result"].(string)
	rec.Status = result
	if details, ok := payload["details"].(map[string]any); ok {
		rec.MatchConfidence = jsonNumberPtr(details["match_confidence"])
		rec.LivenessPassed = boolPtr(details["liveness_passed"])
	}
	if err := storeFaceRecord(state.tokenStorage, rec); err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to persist face result", err,
			"endpoint", endpoint, "face_session_id", faceSessionID)
		return
	}

	slog.Info("recorded face verification result",
		"face_session_id", faceSessionID, "result", result)

	if err := writeJSON(w, http.StatusOK, FaceCallbackResponse{Ok: true}); err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_MARSHAL, err)
	}
}

// verifyCallbackSignature recomputes HMAC-SHA256(binding_secret, canonical(body
// without signature)) and compares it (constant time) against the hex signature
// carried in the body.
func verifyCallbackSignature(payload map[string]any, bindingSecret string) bool {
	received, ok := payload["signature"].(string)
	if !ok || received == "" || bindingSecret == "" {
		return false
	}

	// Compare against a copy without the signature field.
	unsigned := make(map[string]any, len(payload))
	for k, v := range payload {
		if k == "signature" {
			continue
		}
		unsigned[k] = v
	}

	canonical, err := canonicalJSON(unsigned)
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, []byte(bindingSecret))
	mac.Write(canonical)
	expected := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expected), []byte(received))
}

// faceGateError carries the HTTP status and verbatim response body for a refused
// gated issuance.
type faceGateError struct {
	code int
	body string
}

func (e *faceGateError) Error() string { return e.body }

// checkFaceGate enforces that face verification succeeded before issuance.
// Returns nil when face verification is not required (disabled or configured
// off) or when the gate passes. Never deletes the session, so the wallet can
// retry once the verdict lands.
func (state *ServerState) checkFaceGate(ctx context.Context, request models.ValidationRequest) *faceGateError {
	if !state.requireFaceForIssuance {
		return nil
	}

	if request.FaceSessionId == "" {
		return &faceGateError{http.StatusForbidden, faceGateRequired}
	}

	rec, err := retrieveFaceRecord(state.tokenStorage, request.FaceSessionId)
	if err != nil {
		slog.Warn("issuance gate: no face record", "face_session_id", request.FaceSessionId, "error", err)
		return &faceGateError{http.StatusForbidden, faceGateRequired}
	}

	// Bind the verdict to the document being issued: the face session must have
	// been created from this document's portrait (DG2 for passports/ID cards,
	// DG6 for driving licences).
	wantHash := portraitSha256Hex(request.DataGroups)
	if wantHash == "" || wantHash != rec.Dg2Sha256 {
		slog.Warn("issuance gate: portrait hash mismatch", "face_session_id", request.FaceSessionId)
		return &faceGateError{http.StatusForbidden, faceGateMismatch}
	}

	status := rec.Status

	// Pull fallback: if the pushed callback has not arrived yet, poll the face
	// service for the authoritative result.
	if (status == "" || status == faceStatusPending) && state.faceStatusGetter != nil {
		if res, perr := state.faceStatusGetter.GetSessionStatus(ctx, request.FaceSessionId); perr == nil && res != nil {
			status = res.Status
			rec.Status = res.Status
			rec.MatchConfidence = res.MatchConfidence
			rec.LivenessPassed = res.LivenessPassed
			if status != "" && status != faceStatusPending {
				if serr := storeFaceRecord(state.tokenStorage, rec); serr != nil {
					slog.Warn("issuance gate: failed to persist polled face result", "error", serr)
				}
			}
		} else if perr != nil {
			slog.Warn("issuance gate: face status poll failed", "face_session_id", request.FaceSessionId, "error", perr)
		}
	}

	switch status {
	case faceStatusSuccess:
		return nil
	case "", faceStatusPending:
		return &faceGateError{http.StatusPreconditionRequired, faceGatePending}
	default:
		return &faceGateError{http.StatusForbidden, faceGateFailed}
	}
}

// readLimitedBody reads up to 1 MiB of the request body.
func readLimitedBody(r *http.Request) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, 1<<20))
}

func jsonNumberPtr(v any) *float64 {
	n, ok := v.(json.Number)
	if !ok {
		return nil
	}
	f, err := n.Float64()
	if err != nil {
		return nil
	}
	return &f
}

func boolPtr(v any) *bool {
	b, ok := v.(bool)
	if !ok {
		return nil
	}
	return &b
}
