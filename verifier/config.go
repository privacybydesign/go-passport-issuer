package main

import (
	"errors"
	"flag"
	"fmt"
	"strconv"
	"time"
)

// Limits are the server-enforced bounds of one stream.
type Limits struct {
	// FPS is the accepted cadence; frames arriving faster are dropped
	// unprocessed and uncounted.
	FPS int
	// MaxFrames is the number of processed frames after which the stream
	// ends with too_many_frames.
	MaxFrames int
	// MaxDuration bounds the stream from its start; longer ends with timeout.
	MaxDuration time.Duration
	// MaxWidth bounds both JPEG dimensions, in pixels.
	MaxWidth int
	// MaxFrameBytes bounds the JPEG size of one frame.
	MaxFrameBytes int64
}

// RedisConfig comes from the Kubernetes secret `redis` in the verifier's
// namespace. Its ACL user is the namespace name and may only touch keys
// under "<username>:".
type RedisConfig struct {
	SentinelHost string
	SentinelPort int
	MasterName   string
	Username     string
	Password     string
}

// Enabled: an empty Sentinel host selects the in-memory store.
func (r RedisConfig) Enabled() bool { return r.SentinelHost != "" }

func (r RedisConfig) KeyPrefix() string { return r.Username + ":iris:" }

type Config struct {
	ListenAddr string
	// PublicStreamURL is the wss:// origin wallets reach this service on. It
	// is reported in logs and readyz only; the issuer builds each session's
	// stream URL itself.
	PublicStreamURL string
	// DistanceThreshold: a completed session passes when the engine's
	// distance is at most this.
	DistanceThreshold float64
	Limits            Limits
	// PendingTTL is how long a created session waits for its stream.
	PendingTTL time.Duration
	// TerminalTTL is how long a finished session stays readable by the issuer.
	TerminalTTL time.Duration
	// HandshakeTimeout bounds the wait for the hello message after connect.
	HandshakeTimeout time.Duration
	LogLevel         string
	Redis            RedisConfig
	// DebugFrameDir, when set, makes the verifier write the first
	// DebugFrameCount processed frames of every session to
	// <dir>/<face_session_id>/ as JPEGs, to inspect what the engine sees.
	// These are biometric images: debugging on staging only, never in
	// production.
	DebugFrameDir   string
	DebugFrameCount int
}

func defaultConfig() Config {
	return Config{
		ListenAddr:        ":8081",
		DistanceThreshold: 0.75,
		Limits: Limits{
			FPS:           15,
			MaxFrames:     900,
			MaxDuration:   60 * time.Second,
			MaxWidth:      640,
			MaxFrameBytes: 1 << 20,
		},
		PendingTTL:       10 * time.Minute,
		TerminalTTL:      15 * time.Minute,
		HandshakeTimeout: 10 * time.Second,
		LogLevel:         "info",
		DebugFrameCount:  20,
		Redis:            RedisConfig{SentinelPort: 26379},
	}
}

type runMode int

const (
	modeServe runMode = iota
	modeWorker
	modeSelftest
)

// parseArgs reads the flags, then the environment. An environment variable
// that is set wins over its flag, because the deployment sets the
// environment and a flag left in an image must not override it. Redis
// settings are environment-only because they carry a secret.
func parseArgs(args []string, getenv func(string) string) (Config, runMode, error) {
	cfg := defaultConfig()
	fs := flag.NewFlagSet("iris-verifier", flag.ContinueOnError)
	fs.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "listen address (IRIS_LISTEN_ADDR)")
	fs.StringVar(&cfg.PublicStreamURL, "public-stream-url", "", "public wss:// origin of this service, for logs and readyz (IRIS_PUBLIC_STREAM_URL)")
	fs.Float64Var(&cfg.DistanceThreshold, "distance-threshold", cfg.DistanceThreshold, "maximum distance for a completed session to pass (IRIS_DISTANCE_THRESHOLD)")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "debug, info, warn or error (IRIS_LOG_LEVEL)")
	fs.IntVar(&cfg.Limits.MaxFrames, "max-frames", cfg.Limits.MaxFrames, "processed frames per session (IRIS_MAX_FRAMES)")
	maxSeconds := fs.Int("max-seconds", seconds(cfg.Limits.MaxDuration), "seconds per session from its start (IRIS_MAX_SECONDS)")
	fs.IntVar(&cfg.Limits.MaxWidth, "max-width", cfg.Limits.MaxWidth, "maximum frame dimension in pixels (IRIS_MAX_WIDTH)")
	fs.IntVar(&cfg.Limits.FPS, "fps", cfg.Limits.FPS, "frames per second accepted; faster frames are dropped (IRIS_FPS)")
	fs.Int64Var(&cfg.Limits.MaxFrameBytes, "max-frame-bytes", cfg.Limits.MaxFrameBytes, "maximum JPEG size per frame (IRIS_MAX_FRAME_BYTES)")
	pendingTTL := fs.Int("pending-ttl-seconds", seconds(cfg.PendingTTL), "how long a session waits for its stream (IRIS_PENDING_TTL_SECONDS)")
	terminalTTL := fs.Int("terminal-ttl-seconds", seconds(cfg.TerminalTTL), "how long a finished session stays readable (IRIS_TERMINAL_TTL_SECONDS)")
	handshake := fs.Int("handshake-timeout-seconds", seconds(cfg.HandshakeTimeout), "wait for the hello message (IRIS_HANDSHAKE_TIMEOUT_SECONDS)")
	fs.StringVar(&cfg.DebugFrameDir, "debug-frame-dir", "", "write the first frames of every session here as JPEGs; staging debugging only (IRIS_DEBUG_FRAME_DIR)")
	fs.IntVar(&cfg.DebugFrameCount, "debug-frame-count", cfg.DebugFrameCount, "frames per session written to debug-frame-dir (IRIS_DEBUG_FRAME_COUNT)")
	worker := fs.Bool("worker", false, "run as a session worker on stdin/stdout (spawned by the server)")
	selftest := fs.Bool("selftest", false, "with --worker: initialise the engine and exit")
	if err := fs.Parse(args); err != nil {
		return Config{}, modeServe, err
	}

	env := envReader{getenv: getenv}
	cfg.ListenAddr = env.str("IRIS_LISTEN_ADDR", cfg.ListenAddr)
	cfg.PublicStreamURL = env.str("IRIS_PUBLIC_STREAM_URL", cfg.PublicStreamURL)
	cfg.DistanceThreshold = env.float("IRIS_DISTANCE_THRESHOLD", cfg.DistanceThreshold)
	cfg.LogLevel = env.str("IRIS_LOG_LEVEL", cfg.LogLevel)
	cfg.Limits.MaxFrames = env.int("IRIS_MAX_FRAMES", cfg.Limits.MaxFrames)
	cfg.Limits.MaxDuration = time.Duration(env.int("IRIS_MAX_SECONDS", *maxSeconds)) * time.Second
	cfg.Limits.MaxWidth = env.int("IRIS_MAX_WIDTH", cfg.Limits.MaxWidth)
	cfg.Limits.FPS = env.int("IRIS_FPS", cfg.Limits.FPS)
	cfg.Limits.MaxFrameBytes = env.int64("IRIS_MAX_FRAME_BYTES", cfg.Limits.MaxFrameBytes)
	cfg.PendingTTL = time.Duration(env.int("IRIS_PENDING_TTL_SECONDS", *pendingTTL)) * time.Second
	cfg.TerminalTTL = time.Duration(env.int("IRIS_TERMINAL_TTL_SECONDS", *terminalTTL)) * time.Second
	cfg.HandshakeTimeout = time.Duration(env.int("IRIS_HANDSHAKE_TIMEOUT_SECONDS", *handshake)) * time.Second
	cfg.DebugFrameDir = env.str("IRIS_DEBUG_FRAME_DIR", cfg.DebugFrameDir)
	cfg.DebugFrameCount = env.int("IRIS_DEBUG_FRAME_COUNT", cfg.DebugFrameCount)
	cfg.Redis = RedisConfig{
		SentinelHost: env.str("REDIS_SENTINEL_HOST", ""),
		SentinelPort: env.int("REDIS_SENTINEL_PORT", cfg.Redis.SentinelPort),
		MasterName:   env.str("REDIS_MASTER_NAME", ""),
		Username:     env.str("REDIS_USERNAME", ""),
		Password:     env.str("REDIS_PASSWORD", ""),
	}
	if env.err != nil {
		return Config{}, modeServe, env.err
	}

	mode := modeServe
	switch {
	case *worker && *selftest:
		mode = modeSelftest
	case *worker:
		mode = modeWorker
	case *selftest:
		return Config{}, modeServe, errors.New("--selftest requires --worker")
	}
	if mode == modeServe {
		if err := cfg.validate(); err != nil {
			return Config{}, modeServe, err
		}
	}
	return cfg, mode, nil
}

func seconds(d time.Duration) int { return int(d / time.Second) }

func (c Config) validate() error {
	switch {
	case c.Limits.FPS < 1:
		return errors.New("fps must be at least 1")
	case c.Limits.MaxFrames < 1:
		return errors.New("max-frames must be at least 1")
	case c.Limits.MaxDuration <= 0:
		return errors.New("max-seconds must be positive")
	case c.Limits.MaxWidth < 1:
		return errors.New("max-width must be at least 1")
	case c.Limits.MaxFrameBytes < 1:
		return errors.New("max-frame-bytes must be at least 1")
	case c.DistanceThreshold <= 0:
		return errors.New("distance-threshold must be positive")
	case c.PendingTTL <= 0 || c.TerminalTTL <= 0 || c.HandshakeTimeout <= 0:
		return errors.New("ttl and handshake-timeout seconds must be positive")
	}
	if c.Redis.Enabled() {
		switch {
		case c.Redis.MasterName == "":
			return errors.New("REDIS_MASTER_NAME is required with REDIS_SENTINEL_HOST")
		case c.Redis.Username == "":
			return errors.New("REDIS_USERNAME is required with REDIS_SENTINEL_HOST")
		case c.Redis.Password == "":
			return errors.New("REDIS_PASSWORD is required with REDIS_SENTINEL_HOST")
		}
	}
	return nil
}

// envReader reads typed environment variables, keeping the first parse error
// so the caller can report it after collecting all values.
type envReader struct {
	getenv func(string) string
	err    error
}

func (e *envReader) str(name, def string) string {
	if v := e.getenv(name); v != "" {
		return v
	}
	return def
}

func (e *envReader) int(name string, def int) int {
	v := e.getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		e.fail(name, err)
		return def
	}
	return n
}

func (e *envReader) int64(name string, def int64) int64 {
	v := e.getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		e.fail(name, err)
		return def
	}
	return n
}

func (e *envReader) float(name string, def float64) float64 {
	v := e.getenv(name)
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		e.fail(name, err)
		return def
	}
	return f
}

func (e *envReader) fail(name string, err error) {
	if e.err == nil {
		e.err = fmt.Errorf("environment variable %s: %w", name, err)
	}
}
