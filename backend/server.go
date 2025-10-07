package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	log "go-passport-issuer/logging"
	"go-passport-issuer/models"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gorilla/mux"
)

const ErrorInternal = "error:internal"
const ERR_MARSHAL = "failed to marshal response message"
const ERR_FAILED_BODY_CLOSE = "failed to close request body: %v"

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
	cscaCertPool  *cms.CombinedCertPool
	validator     PassportValidator
	converter     PassportDataConverter
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

	router.HandleFunc("/api/start-validation", func(w http.ResponseWriter, r *http.Request) {
		handleStartValidatePassport(state, w, r)
	})
	router.HandleFunc("/api/verify-and-issue", func(w http.ResponseWriter, r *http.Request) {
		handleIssuePassport(state, w, r)
	})
	router.HandleFunc("/api/verify-passport", func(w http.ResponseWriter, r *http.Request) {
		handleVerifyPassport(state, w, r)
	})
	router.HandleFunc("/.well-known/apple-app-site-association", HandleAssaRequest).Methods(http.MethodGet)
	router.HandleFunc("/apple-app-site-association", HandleAssaRequest).Methods(http.MethodGet)
	router.HandleFunc("/.well-known/assetlinks.json", HandleAssetLinksRequest).Methods(http.MethodGet)

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

type PassportIssuanceResponse struct {
	Jwt           string `json:"jwt"`
	IrmaServerURL string `json:"irma_server_url"`
}

type PassportVerificationResponse struct {
	AuthenticContent bool `json:"authentic_content"`
	AuthenticChip    bool `json:"authentic_chip"`
	IsExpired        bool `json:"is_expired"`
}

func handleVerifyPassport(state *ServerState, w http.ResponseWriter, r *http.Request) {
	defer closeRequestBody(r)

	if !requirePOST(w, r) {
		return
	}

	log.Info.Printf("Received request to do verify a passport readout")

	doc, activeAuth, request, err := VerifyPassportRequest(r, state)
	if err != nil {
		respondWithErr(w, http.StatusBadRequest, "invalid request", "failed to verify passport", err)
		return
	}

	passportData, err := state.converter.ToPassportData(doc, activeAuth)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to convert to issuance request", err)
		return
	}

	// check expired
	isExpired := passportData.DateOfExpiry.Before(time.Now())

	// set up the response
	verificationResponse := PassportVerificationResponse{
		true,
		activeAuth,
		isExpired,
	}

	response := verificationResponse

	if err := writeJSON(w, http.StatusOK, response); err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_MARSHAL, err)
		return
	}

	// Remove the sessionID from the cache
	err = state.tokenStorage.RemoveToken(request.SessionId)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to remove token from storage", err)
		return
	}

}

func handleIssuePassport(state *ServerState, w http.ResponseWriter, r *http.Request) {
	defer closeRequestBody(r)

	if !requirePOST(w, r) {
		return
	}

	log.Info.Printf("Received request to verify and issue passport")

	doc, activeAuth, request, err := VerifyPassportRequest(r, state)
	if err != nil {
		respondWithErr(w, http.StatusBadRequest, "invalid request", "failed to verify passport", err)
		return
	}

	var issuanceRequest models.PassportData
	issuanceRequest, err = state.converter.ToPassportData(doc, activeAuth)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to convert to issuance request", err)
		return
	}

	jwt, err := state.jwtCreator.CreateJwt(issuanceRequest)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, "failed to create JWT", "failed to create JWT", err)
		return
	}

	response := PassportIssuanceResponse{
		Jwt:           jwt,
		IrmaServerURL: state.irmaServerURL,
	}

	if err := writeJSON(w, http.StatusOK, response); err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_MARSHAL, err)
		return
	}

	// Remove the sessionID from the cache
	err = state.tokenStorage.RemoveToken(request.SessionId)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to remove token from storage", err)
		return
	}

}

func VerifyPassportRequest(r *http.Request, state *ServerState) (document.Document, bool, models.PassportValidationRequest, error) {
	var request models.PassportValidationRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		return document.Document{}, false, request, fmt.Errorf("decode request body: %w", err)
	}

	// Check if the sessionId and nonce are in the cache
	nonce, err := state.tokenStorage.RetrieveToken(request.SessionId)
	if err != nil {
		return document.Document{}, false, request, fmt.Errorf("failed to get nonce from storage: %w", err)
	}

	if nonce == "" || nonce != request.Nonce {
		return document.Document{}, false, request, fmt.Errorf("invalid session or nonce")
	}

	var doc document.Document
	doc, err = state.validator.Passive(request, state.cscaCertPool)
	if err != nil {
		return document.Document{}, false, request, fmt.Errorf("passive authentication failed: %w", err)
	}

	activeAuth, err := state.validator.Active(request, doc)
	if err != nil {
		return document.Document{}, false, request, fmt.Errorf("active authentication failed: %w", err)
	}

	return doc, activeAuth, request, nil
}

// -----------------------------------------------------------------------------------

type ValidatePassportResponse struct {
	SessionId string `json:"session_id"`
	Nonce     string `json:"nonce"`
}

func handleStartValidatePassport(state *ServerState, w http.ResponseWriter, r *http.Request) {
	defer closeRequestBody(r)

	if !requirePOST(w, r) {
		return
	}

	log.Info.Printf("Received request to start passport validation")

	// Generate a session ID
	sessionId := GenerateSessionId()
	if sessionId == "" {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to generate session ID", fmt.Errorf("failed to generate session ID"))
		return
	}

	// Generate an 8 byte nonce
	nonce, err := GenerateNonce(8)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to generate nonce", err)
		return
	}

	// Store the nonce in Redis, should be removed when the jwt is handed over to the app
	err = state.tokenStorage.StoreToken(sessionId, nonce)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to store nonce", err)
		return
	}

	response := ValidatePassportResponse{
		SessionId: sessionId,
		Nonce:     string(nonce),
	}

	if err := writeJSON(w, http.StatusOK, response); err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_MARSHAL, err)
		return
	}

}

//go:embed associations/android_asset_links.json
var assetlinksJson []byte

func HandleAssetLinksRequest(w http.ResponseWriter, r *http.Request) {
	writeStaticJSON(w, assetlinksJson)
}

//go:embed associations/apple-app-site-association.json
var appleAssociationJson []byte

func HandleAssaRequest(w http.ResponseWriter, r *http.Request) {
	writeStaticJSON(w, appleAssociationJson)

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

// helpers ------------

func writeStaticJSON(w http.ResponseWriter, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if _, err := w.Write(b); err != nil {
		log.Error.Fatalf("failed to write body to http response: %v", err)
	}
}

func closeRequestBody(r *http.Request) {
	if err := r.Body.Close(); err != nil {
		log.Error.Printf(ERR_FAILED_BODY_CLOSE, err)
	}

}

func requirePOST(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		respondWithErr(w, http.StatusMethodNotAllowed, "method not allowed", "invalid method", nil)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(payload)
	if err != nil {
		log.Error.Fatalf("failed to write body to http response: %v", err)
	}
	return nil
}
