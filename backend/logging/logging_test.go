package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultLoggersInitialized(t *testing.T) {
	require.NotNil(t, Info, "Info logger should be initialized")
	require.NotNil(t, Error, "Error logger should be initialized")
}

func TestDefaultLoggersPrefix(t *testing.T) {
	require.NotNil(t, Info)
	require.NotNil(t, Error)

	// Check that loggers have the correct prefix
	require.Equal(t, "INFO: ", Info.Prefix())
	require.Equal(t, "ERROR: ", Error.Prefix())
}

func TestInitFileLogger(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	// Initialize file logger
	InitFileLogger(logFile)

	// Verify loggers are set up
	require.NotNil(t, Info)
	require.NotNil(t, Error)

	// Verify the log file was created
	_, err := os.Stat(logFile)
	require.NoError(t, err, "Log file should be created")

	// Test writing to the loggers
	Info.Println("Test info message")
	Error.Println("Test error message")

	// Read the log file and verify content
	content, err := os.ReadFile(logFile)
	require.NoError(t, err)

	logContent := string(content)
	require.Contains(t, logContent, "INFO:")
	require.Contains(t, logContent, "Test info message")
	require.Contains(t, logContent, "ERROR:")
	require.Contains(t, logContent, "Test error message")
}

func TestInitFileLoggerInvalidPath(t *testing.T) {
	// Create a path that cannot be created (invalid directory)
	invalidPath := "/nonexistent/directory/test.log"

	// This should panic or cause a fatal error
	// We'll test that it doesn't return successfully
	defer func() {
		if r := recover(); r == nil {
			// If we get here without panic, the file might have been created
			// (unlikely but possible with permissions)
			_, err := os.Stat(invalidPath)
			if err == nil {
				// Clean up if somehow created
				err = os.Remove(invalidPath)
				if err != nil {
					t.Fatal("failed removing the log file")
				}
			}
		}
	}()

	// Note: InitFileLogger calls log.Fatalf on error which exits the process
	// In a real scenario, this would need to be refactored to return an error
	// For now, we'll skip this test case since it would kill the test process
	t.Skip("InitFileLogger calls log.Fatalf which would terminate the test process")
}

func TestLoggerFlags(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "flags_test.log")

	InitFileLogger(logFile)

	// Write a test message
	Info.Println("Flag test")

	// Read and verify the format includes date/time/file
	content, err := os.ReadFile(logFile)
	require.NoError(t, err)

	logLine := string(content)
	// Check for date format (YYYY/MM/DD)
	require.True(t, strings.Contains(logLine, "/"), "Log should contain date separators")
	// Check for time format (HH:MM:SS)
	require.True(t, strings.Contains(logLine, ":"), "Log should contain time separators")
	// Check for file reference
	require.True(t, strings.Contains(logLine, ".go:"), "Log should contain file reference")
}
