// Package analytics records face verification attempts so the two face
// verification methods (Regula and Iris) can be compared on usage, success
// rate and score distribution.
//
// It is not behavioural analytics, despite the name. Yivi keeps no
// server-side record of what a user does, and nothing here changes that. What
// is measured is the two methods, never a person: no user, no session id, no
// document, and nothing that can be joined back to one. Keep it that way when
// adding fields.
//
// An attempt is one document session's pass through the face verification
// step, counted against the method it was assigned. This package owns the
// vocabulary both services record it in, which is why it is shared: the
// comparison is only meaningful if the issuer and the Iris verifier use the
// same words for the same outcomes.
//
// Every record is coarse and non-identifying: it names a method, a document
// type and a few build labels, never a user, a session id or a document. The
// passport issuer records assignments and issuance outcomes; the Iris
// verifier records stream-level outcomes through the same interface, so one
// set of log queries (or, later, one Prometheus scrape) covers both arms.
//
// The default implementation writes one JSON line per record to stderr
// through slog (see NewStderrRecorder). A Prometheus implementation is the
// planned first alternative; the interface is the seam for it.
package analytics

import "context"

// Method is a face verification method as named on the wire.
type Method string

const (
	MethodRegula Method = "regula"
	MethodIris   Method = "iris"
)

// Kind says which stage of an attempt a record describes.
type Kind string

const (
	// KindAssigned: the issuer assigned a method to a document session.
	KindAssigned Kind = "assigned"
	// KindIssuance: an issuance request was gated on face verification.
	KindIssuance Kind = "issuance"
	// KindIrisSession: an Iris verifier stream reached a terminal state.
	KindIrisSession Kind = "iris_session"
)

// AttemptKind says whether the attempt was the first for its document flow or
// a retry of an earlier one.
type AttemptKind string

const (
	AttemptFirst AttemptKind = "first"
	AttemptRetry AttemptKind = "retry"
)

// Outcomes shared by both methods for KindIssuance records.
const (
	OutcomePassed             = "passed"
	OutcomeMatchRejected      = "match_rejected"
	OutcomeLivenessRejected   = "liveness_rejected"
	OutcomeEvidenceMissing    = "evidence_missing"
	OutcomeAssignmentMismatch = "assignment_mismatch"
	OutcomeError              = "error"
)

// Outcomes for KindIrisSession records.
const (
	OutcomeCompleted = "completed"
	OutcomeFailed    = "failed"
	OutcomeAbandoned = "abandoned"
	OutcomeTimeout   = "timeout"
)

// ScoreKind names the scale a score is on. The two engines score on
// incompatible scales, so a score is never reported without its kind.
type ScoreKind string

const (
	// ScoreRegulaSimilarity: Regula similarity, 0–1, higher is better.
	ScoreRegulaSimilarity ScoreKind = "regula_similarity"
	// ScoreIrisDistance: Iris embedding distance, lower is better.
	ScoreIrisDistance ScoreKind = "iris_distance"
)

// Client describes the wallet build that made the attempt, as declared by the
// wallet in the start-validation `client` block. All fields are empty for
// wallets released before the block existed.
type Client struct {
	Platform   string `json:"platform,omitempty"`
	Flavor     string `json:"flavor,omitempty"`
	AppVersion string `json:"app_version,omitempty"`
}

// Record is one observation about an attempt. Zero-valued fields are omitted
// from the output, so a record carries only what its Kind knows.
type Record struct {
	Kind   Kind   `json:"kind"`
	Method Method `json:"method"`
	Client Client `json:"client,omitzero"`
	// DocumentType is "passport", "id_card" or "driving_licence".
	DocumentType string      `json:"document_type,omitempty"`
	AttemptKind  AttemptKind `json:"attempt_kind,omitempty"`
	Outcome      string      `json:"outcome,omitempty"`
	// Score is set only when the engine produced one; ScoreKind then says
	// which scale it is on.
	Score     *float64  `json:"score,omitempty"`
	ScoreKind ScoreKind `json:"score_kind,omitempty"`
	// DurationMs is wallet-reported for issuance records (intro confirmation
	// to evidence in hand) and measured server-side for iris_session records.
	DurationMs *int64 `json:"duration_ms,omitempty"`
	// Frames and PerFrameMs are iris_session only.
	Frames     *int     `json:"frames,omitempty"`
	PerFrameMs *float64 `json:"per_frame_ms,omitempty"`
}

// Recorder receives records about face verification attempts. Implementations
// must be safe for concurrent use and must never block the caller for long:
// recording is observability, not part of the verdict.
type Recorder interface {
	Record(ctx context.Context, e Record)
}

// Float64 returns a pointer to v, for the optional score fields.
func Float64(v float64) *float64 { return &v }

// Int64 returns a pointer to v, for the optional duration field.
func Int64(v int64) *int64 { return &v }

// Int returns a pointer to v, for the optional frame count.
func Int(v int) *int { return &v }
