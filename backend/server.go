package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	log "go-passport-issuer/logging"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gorilla/mux"
)

const ErrorInternal = "error:internal"

type ServerConfig struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	UseTls         bool   `json:"use_tls,omitempty"`
	TlsPrivKeyPath string `json:"tls_priv_key_path,omitempty"`
	TlsCertPath    string `json:"tls_cert_path,omitempty"`
}

type ServerState struct {
	irmaServerURL string
	tokenStorage  TokenStorage
	jwtCreator    JwtCreator
}

type SpaHandler struct {
	staticPath string
	indexPath  string
}

type Server struct {
	server *http.Server
	config ServerConfig
}

func (s *Server) ListenAndServe() error {
	if s.config.UseTls {
		return s.server.ListenAndServeTLS(s.config.TlsCertPath, s.config.TlsPrivKeyPath)
	} else {
		return s.server.ListenAndServe()
	}
}

func (s *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

// ServeHTTP inspects the URL path to locate a file within the static dir
// on the SPA handler. If a file is found, it will be served. If not, the
// file located at the index path on the SPA handler will be served. This
// is suitable behavior for serving an SPA (single page application).
// https://github.com/gorilla/mux?tab=readme-ov-file#serving-single-page-applications
func (h SpaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Join internally call path.Clean to prevent directory traversal
	path := filepath.Join(h.staticPath, r.URL.Path)
	// check whether a file exists or is a directory at the given path
	fi, err := os.Stat(path)
	if os.IsNotExist(err) || fi.IsDir() {
		// file does not exist or path is a directory, serve index.html
		http.ServeFile(w, r, filepath.Join(h.staticPath, h.indexPath))
		return
	}

	if err != nil {
		// if we got an error (that wasn't that the file doesn't exist) stating the
		// file, return a 500 internal server error and stop
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// otherwise, use http.FileServer to serve the static file
	http.FileServer(http.Dir(h.staticPath)).ServeHTTP(w, r)
}

func NewServer(state *ServerState, config ServerConfig) (*Server, error) {
	router := mux.NewRouter()

	router.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		err := json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		if err != nil {
			log.Error.Fatalf("failed to write body to http response: %v", err)
		}
	})

	router.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		handleValidatePassport(state, w, r)
	})
	router.HandleFunc("/issue", func(w http.ResponseWriter, r *http.Request) {
		handleIssuePassport(state, w, r)
	})
	spa := SpaHandler{staticPath: "../frontend/build", indexPath: "index.html"}
	router.PathPrefix("/").Handler(spa)

	addr := fmt.Sprintf("%v:%v", config.Host, config.Port)
	srv := &http.Server{
		Handler: router,
		Addr:    addr,
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	return &Server{
		server: srv,
		config: config,
	}, nil
}

type PassportIssuanceRequest struct {
	SessionId string `json:"session_id"`
	Nonce     string `json:"nonce"`
	// Passport details
	Photo                string    `json:"photo,omitempty"` // base64 or image URL, optional
	DocumentNumber       string    `json:"document_number"`
	DocumentType         string    `json:"document_type"`
	FirstName            string    `json:"first_name"`
	LastName             string    `json:"last_name"`
	Nationality          string    `json:"nationality"`
	DateOfBirth          time.Time `json:"date_of_birth"`
	DateOfExpiry         time.Time `json:"date_of_expiry"`
	Gender               string    `json:"gender"`
	Country              string    `json:"country"`
	Over12               bool      `json:"over12"`
	Over16               bool      `json:"over16"`
	Over18               bool      `json:"over18"`
	Over21               bool      `json:"over21"`
	Over65               bool      `json:"over65"`
	ActiveAuthentication bool      `json:"active_authentication"`
}

type PassportIssuanceResponse struct {
	Jwt           string `json:"jwt"`
	IrmaServerURL string `json:"irma_server_url"`
}

func handleIssuePassport(state *ServerState, w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Error.Printf("failed to close request body: %v", err)
		}
	}()

	if r.Method != http.MethodPost {
		respondWithErr(w, http.StatusMethodNotAllowed, "method not allowed", "invalid method", nil)
		return
	}

	var request PassportIssuanceRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		respondWithErr(w, http.StatusBadRequest, "invalid request body", "failed to decode request body", err)
		return
	}

	// Check if the sessionId and nonce are in the cache
	nonce, err := state.tokenStorage.RetrieveToken(request.SessionId)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to get nonce from storage", err)
		return
	}

	if nonce == "" || nonce != request.Nonce {
		respondWithErr(w, http.StatusBadRequest, "invalid session or nonce", "session or nonce is invalid", nil)
		return
	}

	jwt, err := state.jwtCreator.CreateJwt(request)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, "failed to create JWT", "failed to create JWT", err)
		return
	}

	responseMessage := PassportIssuanceResponse{
		Jwt:           jwt,
		IrmaServerURL: state.irmaServerURL,
	}

	payload, err := json.Marshal(responseMessage)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to marshal response message", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(payload)
	if err != nil {
		log.Error.Fatalf("failed to write body to http response: %v", err)
	}
}

// -----------------------------------------------------------------------------------

type ValidatePassportResponse struct {
	SessionId string `json:"session_id"`
	Nonce     string `json:"nonce"`
}

func handleValidatePassport(state *ServerState, w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Error.Printf("failed to close request body: %v", err)
		}
	}()

	if r.Method != http.MethodPost {
		respondWithErr(w, http.StatusMethodNotAllowed, "method not allowed", "invalid method", nil)
		return
	}

	// Generate a session ID
	sessionId := GenerateSessionId()
	if sessionId == "" {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to generate session ID", fmt.Errorf("failed to generate session ID"))
		return
	}

	// Generate an 8 bit nonce
	nonce, err := GenerateNonce(8)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to generate nonce", err)
		return
	}

	// Store the nonce in Redis with a 5 minute expiration
	err = state.tokenStorage.StoreToken(sessionId, nonce)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to store nonce", err)
		return
	}

	response := ValidatePassportResponse{
		SessionId: sessionId,
		Nonce:     string(nonce),
	}

	payload, err := json.Marshal(response)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to marshal response message", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(payload)
	if err != nil {
		log.Error.Fatalf("failed to write body to http response: %v", err)
	}
}

func GenerateSessionId() string {
	sessionId := make([]byte, 16)
	if _, err := rand.Read(sessionId); err != nil {
		log.Error.Printf("failed to generate session ID: %v", err)
		return ""
	}
	return fmt.Sprintf("%x", sessionId)
}

// Generates a random nonce
func GenerateNonce(i int) (string, error) {
	nonce := make([]byte, i)
	if _, err := rand.Read(nonce); err != nil {
		log.Error.Printf("failed to generate nonce: %v", err)
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	hexString := hex.EncodeToString(nonce)
	return hexString, nil
}

func respondWithErr(w http.ResponseWriter, code int, responseBody string, logMsg string, e error) {
	m := fmt.Sprintf("%v: %v", logMsg, e)
	log.Error.Printf("%s\n -> returning statuscode %d with message %v", m, code, responseBody)
	w.WriteHeader(code)
	if _, err := w.Write([]byte(responseBody)); err != nil {
		log.Error.Printf("failed to write body to http response: %v", err)
	}
}
