package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestParseArgsDefaults(t *testing.T) {
	cfg, mode, err := parseArgs(nil, envOf(nil))
	require.NoError(t, err)
	require.Equal(t, modeServe, mode)
	require.Equal(t, defaultConfig(), cfg)
	require.Equal(t, ":8081", cfg.ListenAddr)
	require.Equal(t, 0.75, cfg.DistanceThreshold)
	require.Equal(t, Limits{FPS: 15, MaxFrames: 900, MaxDuration: time.Minute, MaxWidth: 640, MaxFrameBytes: 1 << 20}, cfg.Limits)
	require.Equal(t, 10*time.Minute, cfg.PendingTTL)
	require.Equal(t, 15*time.Minute, cfg.TerminalTTL)
	require.Equal(t, 10*time.Second, cfg.HandshakeTimeout)
	require.Equal(t, "info", cfg.LogLevel)
	require.False(t, cfg.Redis.Enabled())
}

func TestParseArgsEnvironment(t *testing.T) {
	env := envOf(map[string]string{
		"IRIS_LISTEN_ADDR":               ":9000",
		"IRIS_PUBLIC_STREAM_URL":         "wss://iris-verifier.staging.yivi.app",
		"IRIS_DISTANCE_THRESHOLD":        "0.6",
		"IRIS_LOG_LEVEL":                 "debug",
		"IRIS_MAX_FRAMES":                "450",
		"IRIS_MAX_SECONDS":               "30",
		"IRIS_MAX_WIDTH":                 "480",
		"IRIS_FPS":                       "10",
		"IRIS_MAX_FRAME_BYTES":           "200000",
		"IRIS_PENDING_TTL_SECONDS":       "300",
		"IRIS_TERMINAL_TTL_SECONDS":      "120",
		"IRIS_HANDSHAKE_TIMEOUT_SECONDS": "5",
		"REDIS_SENTINEL_HOST":            "redis-sentinel-svc.redis",
		"REDIS_SENTINEL_PORT":            "26380",
		"REDIS_MASTER_NAME":              "yivi-master",
		"REDIS_USERNAME":                 "iris-verifier",
		"REDIS_PASSWORD":                 "s3cret",
	})
	cfg, _, err := parseArgs(nil, env)
	require.NoError(t, err)
	require.Equal(t, ":9000", cfg.ListenAddr)
	require.Equal(t, "wss://iris-verifier.staging.yivi.app", cfg.PublicStreamURL)
	require.Equal(t, 0.6, cfg.DistanceThreshold)
	require.Equal(t, "debug", cfg.LogLevel)
	require.Equal(t, Limits{FPS: 10, MaxFrames: 450, MaxDuration: 30 * time.Second, MaxWidth: 480, MaxFrameBytes: 200000}, cfg.Limits)
	require.Equal(t, 5*time.Minute, cfg.PendingTTL)
	require.Equal(t, 2*time.Minute, cfg.TerminalTTL)
	require.Equal(t, 5*time.Second, cfg.HandshakeTimeout)
	require.True(t, cfg.Redis.Enabled())
	require.Equal(t, RedisConfig{SentinelHost: "redis-sentinel-svc.redis", SentinelPort: 26380, MasterName: "yivi-master", Username: "iris-verifier", Password: "s3cret"}, cfg.Redis)
	require.Equal(t, "iris-verifier:iris:", cfg.Redis.KeyPrefix())
}

// Flags work on their own, and a set environment variable beats its flag.
func TestParseArgsFlagsThenEnvWins(t *testing.T) {
	cfg, _, err := parseArgs([]string{"--fps", "12", "--max-seconds", "45", "--pending-ttl-seconds", "60", "--listen", ":1"}, envOf(nil))
	require.NoError(t, err)
	require.Equal(t, 12, cfg.Limits.FPS)
	require.Equal(t, 45*time.Second, cfg.Limits.MaxDuration)
	require.Equal(t, time.Minute, cfg.PendingTTL)
	require.Equal(t, ":1", cfg.ListenAddr)

	cfg, _, err = parseArgs([]string{"--fps", "12", "--listen", ":1"}, envOf(map[string]string{"IRIS_FPS": "20", "IRIS_LISTEN_ADDR": ":2"}))
	require.NoError(t, err)
	require.Equal(t, 20, cfg.Limits.FPS)
	require.Equal(t, ":2", cfg.ListenAddr)
}

func TestParseArgsBadEnv(t *testing.T) {
	_, _, err := parseArgs(nil, envOf(map[string]string{"IRIS_FPS": "fast"}))
	require.ErrorContains(t, err, "IRIS_FPS")
}

func TestParseArgsRedisNeedsCredentials(t *testing.T) {
	_, _, err := parseArgs(nil, envOf(map[string]string{"REDIS_SENTINEL_HOST": "h", "REDIS_MASTER_NAME": "m"}))
	require.ErrorContains(t, err, "REDIS_USERNAME")
}

func TestParseArgsModes(t *testing.T) {
	_, mode, err := parseArgs([]string{"--worker"}, envOf(nil))
	require.NoError(t, err)
	require.Equal(t, modeWorker, mode)

	_, mode, err = parseArgs([]string{"--worker", "--selftest"}, envOf(nil))
	require.NoError(t, err)
	require.Equal(t, modeSelftest, mode)

	_, _, err = parseArgs([]string{"--selftest"}, envOf(nil))
	require.Error(t, err)
}

func TestParseArgsValidation(t *testing.T) {
	_, _, err := parseArgs([]string{"--fps", "0"}, envOf(nil))
	require.ErrorContains(t, err, "fps")
	_, _, err = parseArgs(nil, envOf(map[string]string{"IRIS_MAX_SECONDS": "0"}))
	require.ErrorContains(t, err, "max-seconds")
}
