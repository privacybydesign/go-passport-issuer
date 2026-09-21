// iris-verifier runs the Iris face verification engine as a service: the
// passport issuer opens a session over an internal HTTP API, the wallet
// streams camera frames over a WebSocket, and the issuer reads the verdict.
// Each stream runs in a child process (this binary with --worker) because the
// engine is process-global.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go-passport-issuer/analytics"
	"go-passport-issuer/redis"
)

func main() {
	cfg, mode, err := parseArgs(os.Args[1:], os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	// Logs go to stderr as JSON. In worker mode stdout is the protocol
	// channel, so nothing may ever be printed there.
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(cfg.LogLevel)}))
	slog.SetDefault(logger)

	switch mode {
	case modeSelftest:
		if err := runSelftest(); err != nil {
			logger.Error("selftest failed", "err", err)
			os.Exit(1)
		}
	case modeWorker:
		eng, err := newEngine()
		if err != nil {
			logger.Error("worker cannot start", "err", err)
			os.Exit(1)
		}
		if err := runWorkerLoop(os.Stdin, os.Stdout, eng); err != nil {
			logger.Error("worker loop", "err", err)
			os.Exit(1)
		}
	default:
		os.Exit(serve(cfg, logger))
	}
}

func serve(cfg Config, logger *slog.Logger) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := openStore(cfg, logger)
	if err != nil {
		logger.Error("open store", "err", err)
		return 1
	}
	workers := newSubprocessFactory(selfExecutable(), []string{"--worker"}, logger)
	srv := newServer(cfg, store, workers, analytics.NewStderrRecorder(logger), time.Now, logger)
	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		// Shutdown does not wait for hijacked WebSocket connections; streams
		// in flight end with the process and the wallet starts a new session.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	logger.Info("iris-verifier listening", "addr", cfg.ListenAddr, "public_stream_url", cfg.PublicStreamURL, "engine", engineAvailable,
		"redis", cfg.Redis.Enabled(), "threshold", cfg.DistanceThreshold,
		"fps", cfg.Limits.FPS, "max_frames", cfg.Limits.MaxFrames, "max_seconds", int(cfg.Limits.MaxDuration/time.Second))
	if !engineAvailable {
		logger.Warn("built without the engine: every stream will end with an internal error")
	}
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("listen", "err", err)
		return 1
	}
	return 0
}

// openStore connects to Redis through Sentinel when configured, else uses the
// in-memory store meant for one local process.
func openStore(cfg Config, logger *slog.Logger) (Store, error) {
	if !cfg.Redis.Enabled() {
		logger.Warn("in-memory session store: single replica only, sessions are lost on restart")
		return newMemoryStore(time.Now), nil
	}
	client, err := redis.NewRedisSentinelClient(&redis.RedisSentinelConfig{
		SentinelHost:     cfg.Redis.SentinelHost,
		SentinelPort:     cfg.Redis.SentinelPort,
		MasterName:       cfg.Redis.MasterName,
		SentinelUsername: cfg.Redis.Username,
		Password:         cfg.Redis.Password,
	})
	if err != nil {
		return nil, err
	}
	logger.Info("redis session store", "sentinel", cfg.Redis.SentinelHost, "master", cfg.Redis.MasterName, "prefix", cfg.Redis.KeyPrefix())
	return newRedisStore(client, cfg.Redis.KeyPrefix()), nil
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}
