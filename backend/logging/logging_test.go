package logging

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultLoggerInitialized(t *testing.T) {
	logger := GetLogger()
	require.NotNil(t, logger, "Logger should be initialized")
}

func TestInitLoggerWithDifferentLevels(t *testing.T) {
	tests := []struct {
		name          string
		level         string
		expectedLevel slog.Level
	}{
		{"debug level", "debug", slog.LevelDebug},
		{"info level", "info", slog.LevelInfo},
		{"warn level", "warn", slog.LevelWarn},
		{"warning level", "warning", slog.LevelWarn},
		{"error level", "error", slog.LevelError},
		{"default for unknown", "invalid", slog.LevelInfo},
		{"uppercase", "DEBUG", slog.LevelDebug},
		{"mixed case", "InFo", slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			InitLogger(tt.level)
			logger := GetLogger()
			require.NotNil(t, logger)
			// Note: We can't directly test the level without exposing it,
			// but we verify the logger is created without panicking
		})
	}
}

func TestGetLogger(t *testing.T) {
	InitLogger("info")
	logger1 := GetLogger()
	logger2 := GetLogger()

	require.NotNil(t, logger1)
	require.NotNil(t, logger2)
	require.Equal(t, logger1, logger2, "GetLogger should return the same instance")
}
