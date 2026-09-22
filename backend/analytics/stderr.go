package analytics

import (
	"context"
	"log/slog"
	"strings"
)

// LogKey is the slog attribute every recorded line carries, so the lines can
// be selected with one filter (`event=face_verification`) in Loki or any
// other log store, regardless of what else the process logs. The field is
// called "event" because that is what it is on the log transport; the thing
// being counted is an attempt, which is what this package is named for.
const LogKey = "event"

// LogValue is the value of LogKey on every recorded line.
const LogValue = "face_verification"

// StderrRecorder writes one structured log line per record at INFO level
// through slog. With the JSON handler the process installs, each line is a
// JSON object whose fields are the Record's fields, which is what the
// derived figures are computed from.
type StderrRecorder struct {
	logger *slog.Logger
}

// NewStderrRecorder returns a recorder writing through the given logger, or
// through slog.Default() when logger is nil.
func NewStderrRecorder(logger *slog.Logger) *StderrRecorder {
	if logger == nil {
		logger = slog.Default()
	}
	return &StderrRecorder{logger: logger}
}

// Record implements Recorder.
func (r *StderrRecorder) Record(ctx context.Context, e Record) {
	attrs := []any{
		LogKey, LogValue,
		"kind", string(e.Kind),
		"method", string(e.Method),
	}
	if len(e.Capabilities) > 0 {
		// Joined rather than emitted as an array: a log store groups a string
		// field, while an array field it has to flatten first.
		names := make([]string, len(e.Capabilities))
		for i, m := range e.Capabilities {
			names[i] = string(m)
		}
		attrs = append(attrs, "capabilities", strings.Join(names, ","))
	}
	if e.Client.Platform != "" {
		attrs = append(attrs, "platform", e.Client.Platform)
	}
	if e.Client.Flavor != "" {
		attrs = append(attrs, "flavor", e.Client.Flavor)
	}
	if e.Client.AppVersion != "" {
		attrs = append(attrs, "app_version", e.Client.AppVersion)
	}
	if e.DocumentType != "" {
		attrs = append(attrs, "document_type", e.DocumentType)
	}
	if e.AttemptKind != "" {
		attrs = append(attrs, "attempt_kind", string(e.AttemptKind))
	}
	if e.Outcome != "" {
		attrs = append(attrs, "outcome", e.Outcome)
	}
	if e.Score != nil {
		attrs = append(attrs, "score", *e.Score, "score_kind", string(e.ScoreKind))
	}
	if e.DurationMs != nil {
		attrs = append(attrs, "duration_ms", *e.DurationMs)
	}
	if e.Frames != nil {
		attrs = append(attrs, "frames", *e.Frames)
	}
	if e.PerFrameMs != nil {
		attrs = append(attrs, "per_frame_ms", *e.PerFrameMs)
	}
	r.logger.Log(ctx, slog.LevelInfo, "face verification attempt", attrs...)
}

// Noop discards every record. Used where no recorder is configured, so
// callers never have to nil-check.
type Noop struct{}

// Record implements Recorder.
func (Noop) Record(context.Context, Record) {}
