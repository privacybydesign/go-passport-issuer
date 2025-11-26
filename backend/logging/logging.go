package logging

import (
	"log/slog"
	"os"
	"strings"
)

var logger *slog.Logger

func init() {
	// Default to INFO level
	InitLogger("info")
}

// InitLogger initializes the global logger with the specified level
func InitLogger(level string) {
	var logLevel slog.Level

	switch strings.ToLower(level) {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn", "warning":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}

	handler := slog.NewTextHandler(os.Stderr, opts)
	logger = slog.New(handler)
	slog.SetDefault(logger)
}

// GetLogger returns the global logger instance
func GetLogger() *slog.Logger {
	return logger
}
