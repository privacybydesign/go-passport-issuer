package main

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"go-passport-issuer/analytics"
)

type server struct {
	cfg       Config
	store     Store
	portraits *portraitBox
	streamer  *streamer
	upgrader  websocket.Upgrader
	// workerCheck is set on builds that carry the engine; readyz runs it.
	workerCheck func(context.Context) error
	now         func() time.Time
	log         *slog.Logger
}

func newServer(cfg Config, store Store, workers WorkerFactory, recorder analytics.Recorder, now func() time.Time, log *slog.Logger) *server {
	portraits := newPortraitBox(now)
	s := &server{
		cfg:       cfg,
		store:     store,
		portraits: portraits,
		streamer: &streamer{
			cfg: cfg, store: store, portraits: portraits, workers: workers,
			recorder: recorder, now: now, log: log,
		},
		upgrader: websocket.Upgrader{
			// The clients are native apps, which send no Origin; the session
			// token is what authorises a stream.
			CheckOrigin: func(*http.Request) bool { return true },
		},
		now: now,
		log: log,
	}
	if engineAvailable {
		s.workerCheck = checkWorkerSpawn
	}
	return s
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("GET /stream/{face_session_id}", s.handleStream)
	mux.HandleFunc("POST /internal/sessions", s.handleCreateSession)
	mux.HandleFunc("GET /internal/sessions/{id}", s.handleGetSession)
	mux.HandleFunc("DELETE /internal/sessions/{id}", s.handleDeleteSession)
	return mux
}

func (s *server) handleStream(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("face_session_id")
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade has already written the HTTP error.
		s.log.Info("websocket upgrade failed", "face_session_id", id, "err", err)
		return
	}
	// The stream checks the JPEG size itself and answers frame_too_large; this
	// slightly larger limit is the backstop that stops reading a hostile
	// message at all.
	conn.SetReadLimit(s.cfg.Limits.MaxFrameBytes + frameHeaderSize + 1024)
	s.streamer.serve(r.Context(), id, conn)
}

func (s *server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// handleReadyz: the store answers and, where the engine is built in, a
// worker can start and initialise it.
func (s *server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		s.log.Warn("readyz: store", "err", err)
		writeError(w, http.StatusServiceUnavailable, "store unavailable")
		return
	}
	if s.workerCheck != nil {
		if err := s.workerCheck(ctx); err != nil {
			s.log.Warn("readyz: worker", "err", err)
			writeError(w, http.StatusServiceUnavailable, "worker cannot start")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":            "ok",
		"engine":            engineAvailable,
		"public_stream_url": s.cfg.PublicStreamURL,
	})
}
