package main

import (
	"context"
	"crypto/rand"
	"embed"
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

const redocHTML = `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Passport Issuer API</title>
    <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
  </head>
  <body>
    <redoc spec-url='/openapi.yaml'></redoc>
  </body>
</html>`

//go:embed docs/swagger.yaml
var openAPISpec []byte

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
	converter     IssuanceRequestConverter
}

type SpaHandler struct {
	staticPath string
	indexPath  string
}

type Server struct {
	server *http.Server
	config ServerConfig
}

type apiHandlers struct {
	state *ServerState
}

func serveOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Cache-Control", "public, max-age=300")
	if _, err := w.Write(openAPISpec); err != nil {
		log.Error.Printf("failed to write OpenAPI response: %v", err)
	}
}

func serveDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	if _, err := w.Write([]byte(redocHTML)); err != nil {
		log.Error.Printf("failed to write docs response: %v", err)
	}
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

	handlers := &apiHandlers{state: state}

	router.HandleFunc("/api/health", handlers.Health).Methods(http.MethodGet)
	router.HandleFunc("/api/start-validation", handlers.StartValidation).Methods(http.MethodPost)
	router.HandleFunc("/api/verify-and-issue", handlers.VerifyAndIssue).Methods(http.MethodPost)
	router.HandleFunc("/openapi.yaml", serveOpenAPISpec).Methods(http.MethodGet)
	router.HandleFunc("/docs", serveDocs).Methods(http.MethodGet)
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

// Health reports whether the API is ready to receive requests.
// @Summary Health check
// @Tags Health
// @Produce json
// @Success 200 {object} map[string]bool
// @Router /api/health [get]
func (h *apiHandlers) Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]bool{"ok": true}); err != nil {
		log.Error.Fatalf("failed to write body to http response: %v", err)
	}
}

type PassportIssuanceResponse struct {
	Jwt           string `json:"jwt"`
	IrmaServerURL string `json:"irma_server_url"`
}

// VerifyAndIssue validates the supplied eMRTD payload and returns an issuance request.
// @Summary Verify and issue passport credential
// @Description Validates the passport data and returns an IRMA issuance request once successful.
// @Tags Passport
// @Accept json
// @Produce json
// @Param request body models.PassportValidationRequest true "Passport validation payload"
// @Success 200 {object} PassportIssuanceResponse
// @Failure 400 {string} string
// @Failure 405 {string} string
// @Failure 500 {string} string
// @Router /api/verify-and-issue [post]
func (h *apiHandlers) VerifyAndIssue(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Error.Printf("failed to close request body: %v", err)
		}
	}()

	if r.Method != http.MethodPost {
		respondWithErr(w, http.StatusMethodNotAllowed, "method not allowed", "invalid method", nil)
		return
	}

	log.Info.Printf("Received request to verify and issue passport")

	var request models.PassportValidationRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		respondWithErr(w, http.StatusBadRequest, "invalid request body", "failed to decode request body", err)
		return
	}

	// Check if the sessionId and nonce are in the cache
	nonce, err := h.state.tokenStorage.RetrieveToken(request.SessionId)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to get nonce from storage", err)
		return
	}

	if nonce == "" || nonce != request.Nonce {
		respondWithErr(w, http.StatusBadRequest, "invalid session or nonce", "session or nonce is invalid", nil)
		return
	}

	var doc document.Document
	doc, err = h.state.validator.Passive(request, h.state.cscaCertPool)
	if err != nil {
		respondWithErr(w, http.StatusBadRequest, "invalid request: passive validation failed", "failed to validate request", err)
		return
	}

	activeAuth, err := h.state.validator.Active(request, doc)
	if err != nil {
		respondWithErr(w, http.StatusBadRequest, "invalid request: active authentication failed", "failed to validate active authentication", err)
		return
	}

	var issuanceRequest models.PassportIssuanceRequest
	issuanceRequest, err = h.state.converter.ToIssuanceRequest(doc, activeAuth)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to convert to issuance request", err)
		return
	}

	jwt, err := h.state.jwtCreator.CreateJwt(issuanceRequest)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, "failed to create JWT", "failed to create JWT", err)
		return
	}

	responseMessage := PassportIssuanceResponse{
		Jwt:           jwt,
		IrmaServerURL: h.state.irmaServerURL,
	}

	payload, err := json.Marshal(responseMessage)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to marshal response message", err)
		return
	}

	// Remove the sessionID from the cache
	err = h.state.tokenStorage.RemoveToken(request.SessionId)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to remove token from storage", err)
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

// StartValidation begins a new passport validation session.
// @Summary Start passport validation
// @Description Creates a validation session and returns identifiers required to continue verification.
// @Tags Passport
// @Produce json
// @Success 200 {object} ValidatePassportResponse
// @Failure 400 {string} string
// @Failure 405 {string} string
// @Failure 500 {string} string
// @Router /api/start-validation [post]
func (h *apiHandlers) StartValidation(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Error.Printf("failed to close request body: %v", err)
		}
	}()

	if r.Method != http.MethodPost {
		respondWithErr(w, http.StatusMethodNotAllowed, "method not allowed", "invalid method", nil)
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
	err = h.state.tokenStorage.StoreToken(sessionId, nonce)
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

//go:embed associations/android_asset_links.json
var assetlinksJson []byte

func HandleAssetLinksRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, err := w.Write(assetlinksJson)
	if err != nil {
		log.Error.Fatalf("failed to write body to http response: %v", err)
	}
}

//go:embed associations/apple-app-site-association.json
var appleAssociationJson []byte

func HandleAssaRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, err := w.Write(appleAssociationJson)
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
