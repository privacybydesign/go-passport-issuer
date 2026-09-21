package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func recordOne(t *testing.T, e Record) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	NewStderrRecorder(logger).Record(context.Background(), e)

	var line map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &line), "line: %s", buf.String())
	return line
}

// Every line carries the selector attribute so the recordings can be pulled
// out of the process's other log lines with one filter.
func TestStderrRecorderMarksEveryLine(t *testing.T) {
	line := recordOne(t, Record{Kind: KindAssigned, Method: MethodRegula})
	require.Equal(t, LogValue, line[LogKey])
	require.Equal(t, "assigned", line["kind"])
	require.Equal(t, "regula", line["method"])
	require.Equal(t, "INFO", line["level"])
}

// Fields a kind does not know are left out rather than written as zero
// values, so a count over `score` only sees attempts that produced one.
func TestStderrRecorderOmitsUnsetFields(t *testing.T) {
	line := recordOne(t, Record{Kind: KindAssigned, Method: MethodIris})
	for _, absent := range []string{"platform", "flavor", "app_version", "document_type",
		"attempt_kind", "outcome", "score", "score_kind", "duration_ms", "frames", "per_frame_ms"} {
		require.NotContains(t, line, absent)
	}
}

func TestStderrRecorderWritesAllFields(t *testing.T) {
	line := recordOne(t, Record{
		Kind:         KindIssuance,
		Method:       MethodIris,
		Client:       Client{Platform: "android", Flavor: "play", AppVersion: "8.3.0"},
		DocumentType: "passport",
		AttemptKind:  AttemptRetry,
		Outcome:      OutcomePassed,
		Score:        Float64(0.41),
		ScoreKind:    ScoreIrisDistance,
		DurationMs:   Int64(4200),
		Frames:       Int(60),
		PerFrameMs:   Float64(12.5),
	})
	require.Equal(t, "android", line["platform"])
	require.Equal(t, "play", line["flavor"])
	require.Equal(t, "8.3.0", line["app_version"])
	require.Equal(t, "passport", line["document_type"])
	require.Equal(t, "retry", line["attempt_kind"])
	require.Equal(t, "passed", line["outcome"])
	require.InDelta(t, 0.41, line["score"], 1e-9)
	require.Equal(t, "iris_distance", line["score_kind"])
	require.EqualValues(t, 4200, line["duration_ms"])
	require.EqualValues(t, 60, line["frames"])
	require.InDelta(t, 12.5, line["per_frame_ms"], 1e-9)
}

// The recorder must never carry anything that identifies a person or a
// document; the event type has no field for it, and this pins the JSON shape.
func TestRecordJSONHasNoIdentifyingFields(t *testing.T) {
	b, err := json.Marshal(Record{Kind: KindAssigned, Method: MethodRegula})
	require.NoError(t, err)
	require.JSONEq(t, `{"kind":"assigned","method":"regula"}`, string(b))
}

func TestNoopDoesNothing(t *testing.T) {
	Noop{}.Record(context.Background(), Record{Kind: KindAssigned})
}
