package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go-passport-issuer/document/edl"
	"go-passport-issuer/models"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gorilla/mux"
)

//go:embed docs/swagger.yaml
var swaggerSpec []byte

//go:embed docs/redoc.html
var redocHTML []byte

const ErrorInternal = "error:internal"
const ERR_MARSHAL = "failed to marshal response message"
const ERR_FAILED_BODY_CLOSE = "failed to close request body: %v"
const ERR_ISSUANCE_CONVERT = "failed to convert to issuance request"
const ERR_JWT_CREATION = "failed to create jwt"
const ERR_TOKEN_REMOVAL = "failed to remove token from storage"
const ERR_TOKEN_RETRIEVAL = "failed to get nonce from storage"
const ERR_PASSIVE_FAILED = "passive authentication failed"
const ERR_ACTIVE_FAILED = "active authentication failed"
const ERR_INVALID_NONCE_SESSION = "invalid session or nonce"
const ERR_PASSPORT_VERIFICATION = "failed to verify passport"

type ServerConfig struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	UseTls         bool   `json:"use_tls,omitempty"`
	TlsPrivKeyPath string `json:"tls_priv_key_path,omitempty"`
	TlsCertPath    string `json:"tls_cert_path,omitempty"`
}

type ServerState struct {
	irmaServerURL          string
	tokenStorage           TokenStorage
	jwtCreators            AllJwtCreators
	passportCertPool       *cms.CombinedCertPool
	drivingLicenceCertPool *cms.CertPool
	documentValidator      DocumentValidator
	drivingLicenceParser   DrivingLicenceParser
	converter              DocumentDataConverter
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

	router.HandleFunc("/api/health", handleHealth).Methods(http.MethodGet)

	router.HandleFunc("/api/start-validation", func(w http.ResponseWriter, r *http.Request) {
		handleStartValidatePassport(state, w, r)
	})
	// Verify and issue is here for backwards comptability. this endpoint can be removed in future versions.
	// Date: 16-12-2025, to be removed after January 2026
	router.HandleFunc("/api/verify-and-issue", func(w http.ResponseWriter, r *http.Request) {
		handleIssuePassport(state, w, r)
	})
	router.HandleFunc("/api/issue-passport", func(w http.ResponseWriter, r *http.Request) {
		handleIssuePassport(state, w, r)
	})
	router.HandleFunc("/api/issue-id-card", func(w http.ResponseWriter, r *http.Request) {
		handleIssueIdCard(state, w, r)
	})
	router.HandleFunc("/api/verify-passport", func(w http.ResponseWriter, r *http.Request) {
		handleVerifyPassport(state, w, r)
	})
	router.HandleFunc("/api/verify-driving-licence", func(w http.ResponseWriter, r *http.Request) {
		handleVerifyDrivingLicence(state, w, r)
	})
	router.HandleFunc("/api/issue-driving-licence", func(w http.ResponseWriter, r *http.Request) {
		handleIssueEDL(state, w, r)
	})
	router.HandleFunc("/.well-known/apple-app-site-association", HandleAssaRequest).Methods(http.MethodGet)
	router.HandleFunc("/apple-app-site-association", HandleAssaRequest).Methods(http.MethodGet)
	router.HandleFunc("/.well-known/assetlinks.json", HandleAssetLinksRequest).Methods(http.MethodGet)

	// API Documentation
	router.HandleFunc("/api/docs", HandleRedocRequest).Methods(http.MethodGet)
	router.HandleFunc("/api/docs/swagger.yaml", HandleSwaggerRequest).Methods(http.MethodGet)

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

// IssuanceResponse contains the JWT and IRMA server URL for credential issuance
type IssuanceResponse struct {
	// Signed JWT containing the IRMA issuance request
	Jwt string `json:"jwt" example:"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."`
	// URL of the IRMA server for credential issuance
	IrmaServerURL string `json:"irma_server_url" example:"https://irma.example.com"`
}

// VerificationResponse contains the result of document verification
type VerificationResponse struct {
	// True if passive authentication (signature verification) succeeded
	AuthenticContent bool `json:"authentic_content" example:"true"`
	// True if active authentication (chip challenge-response) succeeded
	AuthenticChip bool `json:"authentic_chip" example:"true"`
	// True if the document has expired
	IsExpired bool `json:"is_expired" example:"false"`
}

// HealthResponse contains the health status of the service
type HealthResponse struct {
	// True if the service is healthy
	Ok bool `json:"ok" example:"true"`
}

// handleHealth returns the health status of the service
// @Summary Health check
// @Description Returns the health status of the API service
// @Tags Health
// @Produce json
// @Success 200 {object} HealthResponse
// @Router /health [get]
func handleHealth(w http.ResponseWriter, r *http.Request) {
	response := HealthResponse{Ok: true}
	if err := writeJSON(w, http.StatusOK, response); err != nil {
		slog.Error("failed to write health response", "error", err)
	}
}

// handleVerifyDrivingLicence verifies driving licence authenticity
// @Summary Verify driving licence authenticity
// @Description Verifies the authenticity of an Electronic Driving Licence (EDL) without issuing credentials. Performs both passive authentication (signature verification) and active authentication (chip challenge-response) if signature is provided.
// @Tags Driving Licence
// @Accept json
// @Produce json
// @Param request body models.ValidationRequest true "Validation request with document data"
// @Success 200 {object} VerificationResponse
// @Failure 400 {string} string "invalid request"
// @Failure 500 {string} string "error:internal"
// @Router /verify-driving-licence [post]
func handleVerifyDrivingLicence(state *ServerState, w http.ResponseWriter, r *http.Request) {
	defer closeRequestBody(r)

	if !requirePOST(w, r) {
		return
	}

	slog.Info("Received request to verify driving license")

	doc, request, activeRes, err := VerifyDrivingLicenceRequest(r, state)
	if err != nil {
		respondWithErr(w, http.StatusBadRequest, "invalid request", "failed to verify driving license", err)
		return
	}

	isExpired := doc.Dg1.DateOfExpiry.Before(time.Now())

	response := VerificationResponse{
		AuthenticContent: true,
		AuthenticChip:    activeRes,
		IsExpired:        isExpired,
	}

	if err := writeJSON(w, http.StatusOK, response); err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_MARSHAL, err)
		return
	}

	removeSessionToken(w, state.tokenStorage, request.SessionId)

}

// handleIssueEDL verifies and issues driving licence credential
// @Summary Verify and issue driving licence credential
// @Description Verifies the Electronic Driving Licence (EDL) and issues an IRMA credential. Returns a JWT that can be used with the IRMA server to obtain the credential.
// @Tags Driving Licence
// @Accept json
// @Produce json
// @Param request body models.ValidationRequest true "Validation request with document data"
// @Success 200 {object} IssuanceResponse
// @Failure 400 {string} string "invalid request"
// @Failure 500 {string} string "error:internal"
// @Router /issue-driving-licence [post]
func handleIssueEDL(state *ServerState, w http.ResponseWriter, r *http.Request) {
	defer closeRequestBody(r)

	if !requirePOST(w, r) {
		return
	}

	slog.Info("Received request to verify and issue driving licence")
	doc, request, activeRes, err := VerifyDrivingLicenceRequest(r, state)

	if err != nil {
		respondWithErr(w, http.StatusBadRequest, "invalid request", "failed to verify driving licence", err)
		return
	}

	issuanceRequest, err := state.converter.ToDrivingLicenceData(*doc, activeRes)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_ISSUANCE_CONVERT, err)
		return
	}

	jwt, err := state.jwtCreators.DrivingLicence.CreateEDLJwt(issuanceRequest)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ERR_JWT_CREATION, ERR_JWT_CREATION, err)
		return
	}

	response := IssuanceResponse{
		Jwt:           jwt,
		IrmaServerURL: state.irmaServerURL,
	}

	if err := writeJSON(w, http.StatusOK, response); err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_MARSHAL, err)
		return
	}

	removeSessionToken(w, state.tokenStorage, request.SessionId)

}

// handleVerifyPassport verifies passport authenticity
// @Summary Verify passport authenticity
// @Description Verifies the authenticity of a passport without issuing credentials. Performs both passive authentication (signature verification) and active authentication (chip challenge-response) if signature is provided.
// @Tags Passport
// @Accept json
// @Produce json
// @Param request body models.ValidationRequest true "Validation request with document data"
// @Success 200 {object} VerificationResponse
// @Failure 400 {string} string "invalid request"
// @Failure 500 {string} string "error:internal"
// @Router /verify-passport [post]
func handleVerifyPassport(state *ServerState, w http.ResponseWriter, r *http.Request) {
	defer closeRequestBody(r)

	if !requirePOST(w, r) {
		return
	}

	slog.Info("Received request to do verify a passport readout")

	doc, activeAuth, request, err := VerifyPassportRequest(r, state)
	if err != nil {
		respondWithErr(w, http.StatusBadRequest, "invalid request", ERR_PASSPORT_VERIFICATION, err)
		return
	}

	passportData, err := state.converter.ToPassportData(doc, activeAuth)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_ISSUANCE_CONVERT, err)
		return
	}

	// check expired
	isExpired := passportData.DateOfExpiry.Before(time.Now())

	// set up the response
	response := VerificationResponse{
		AuthenticContent: true,
		AuthenticChip:    activeAuth,
		IsExpired:        isExpired,
	}

	if err := writeJSON(w, http.StatusOK, response); err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_MARSHAL, err)
		return
	}

	removeSessionToken(w, state.tokenStorage, request.SessionId)

}

// handleIssueIdCard verifies and issues ID card credential
// @Summary Verify and issue ID card credential
// @Description Verifies the ID card and issues an IRMA credential. Returns a JWT that can be used with the IRMA server to obtain the credential.
// @Tags ID Card
// @Accept json
// @Produce json
// @Param request body models.ValidationRequest true "Validation request with document data"
// @Success 200 {object} IssuanceResponse
// @Failure 400 {string} string "invalid request"
// @Failure 500 {string} string "error:internal"
// @Router /issue-id-card [post]
func handleIssueIdCard(state *ServerState, w http.ResponseWriter, r *http.Request) {
	defer closeRequestBody(r)

	if !requirePOST(w, r) {
		return
	}

	slog.Info("Received request to verify and issue id card")

	doc, activeAuth, request, err := VerifyPassportRequest(r, state)
	if err != nil {
		respondWithErr(w, http.StatusBadRequest, "invalid request", ERR_PASSPORT_VERIFICATION, err)
		return
	}

	issuanceRequest, err := state.converter.ToPassportData(doc, activeAuth)

	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_ISSUANCE_CONVERT, err)
		return
	}

	jwt, err := state.jwtCreators.IdCard.CreateIdCardJwt(issuanceRequest)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ERR_JWT_CREATION, ERR_JWT_CREATION, err)
		return
	}

	response := IssuanceResponse{
		Jwt:           jwt,
		IrmaServerURL: state.irmaServerURL,
	}

	if err := writeJSON(w, http.StatusOK, response); err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_MARSHAL, err)
		return
	}

	removeSessionToken(w, state.tokenStorage, request.SessionId)
}

// handleIssuePassport verifies and issues passport credential
// @Summary Verify and issue passport credential
// @Description Verifies the passport and issues an IRMA credential. Returns a JWT that can be used with the IRMA server to obtain the credential.
// @Tags Passport
// @Accept json
// @Produce json
// @Param request body models.ValidationRequest true "Validation request with document data"
// @Success 200 {object} IssuanceResponse
// @Failure 400 {string} string "invalid request"
// @Failure 500 {string} string "error:internal"
// @Router /issue-passport [post]
func handleIssuePassport(state *ServerState, w http.ResponseWriter, r *http.Request) {
	defer closeRequestBody(r)

	if !requirePOST(w, r) {
		return
	}

	slog.Info("Received request to verify and issue passport")

	doc, activeAuth, request, err := VerifyPassportRequest(r, state)
	if err != nil {
		respondWithErr(w, http.StatusBadRequest, "invalid request", ERR_PASSPORT_VERIFICATION, err)
		return
	}

	issuanceRequest, err := state.converter.ToPassportData(doc, activeAuth)

	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_ISSUANCE_CONVERT, err)
		return
	}

	jwt, err := state.jwtCreators.Passport.CreatePassportJwt(issuanceRequest)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ERR_JWT_CREATION, ERR_JWT_CREATION, err)
		return
	}

	response := IssuanceResponse{
		Jwt:           jwt,
		IrmaServerURL: state.irmaServerURL,
	}

	if err := writeJSON(w, http.StatusOK, response); err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_MARSHAL, err)
		return
	}

	removeSessionToken(w, state.tokenStorage, request.SessionId)
}

func VerifyPassportRequest(r *http.Request, state *ServerState) (document.Document, bool, models.ValidationRequest, error) {

	request, err := decodeValidationRequest(r)
	if err != nil {
		return document.Document{}, false, request, err
	}

	if err := validateSession(state.tokenStorage, request.SessionId, request.Nonce); err != nil {
		return document.Document{}, false, request, err
	}

	var doc document.Document
	doc, err = state.documentValidator.PassivePassport(request, state.passportCertPool)
	if err != nil {
		return document.Document{}, false, request, fmt.Errorf("%s: %w", ERR_PASSIVE_FAILED, err)
	}

	activeAuth, err := state.documentValidator.ActivePassport(request, doc)
	if err != nil {
		return document.Document{}, false, request, fmt.Errorf("%s: %w", ERR_ACTIVE_FAILED, err)
	}

	return doc, activeAuth, request, nil
}

func VerifyDrivingLicenceRequest(r *http.Request, state *ServerState) (doc *edl.DrivingLicenceDocument, request models.ValidationRequest, activeRes bool, err error) {

	request, err = decodeValidationRequest(r)
	if err != nil {
		return doc, request, false, err
	}

	if err := validateSession(state.tokenStorage, request.SessionId, request.Nonce); err != nil {
		return doc, request, false, err
	}

	err = state.documentValidator.PassiveEDL(request, state.drivingLicenceCertPool)
	if err != nil {
		return doc, request, false, fmt.Errorf("%s: %w", ERR_PASSIVE_FAILED, err)
	}

	result, err := state.documentValidator.ActiveEDL(request)
	if err != nil {
		return doc, request, false, fmt.Errorf("%s: %w", ERR_ACTIVE_FAILED, err)
	}

	doc, err = state.drivingLicenceParser.ParseEDLDocument(request.DataGroups, request.EFSOD)
	if err != nil {
		return doc, request, false, fmt.Errorf("failed to parse EDL document: %w", err)
	}
	return doc, request, result, nil
}

// -----------------------------------------------------------------------------------

// validateSession validates session and nonce
func validateSession(storage TokenStorage, sessionId, nonce string) error {
	storedNonce, err := storage.RetrieveToken(sessionId)
	if err != nil {
		return fmt.Errorf("%s: %w", ERR_TOKEN_RETRIEVAL, err)
	}

	if storedNonce == "" || storedNonce != nonce {
		return fmt.Errorf("%s", ERR_INVALID_NONCE_SESSION)
	}

	return nil
}

// removeSessionToken removes token and logs error if failed
func removeSessionToken(w http.ResponseWriter, storage TokenStorage, sessionId string) {
	if err := storage.RemoveToken(sessionId); err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_TOKEN_REMOVAL, err)
	}
}

// decodeValidationRequest decodes the request body
func decodeValidationRequest(r *http.Request) (models.ValidationRequest, error) {
	var request models.ValidationRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		return request, fmt.Errorf("decode request body: %w", err)
	}
	return request, nil
}

// ValidatePassportResponse contains the session ID and nonce for document validation
type ValidatePassportResponse struct {
	// Unique session identifier (32 hex characters)
	SessionId string `json:"session_id" example:"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"`
	// Random nonce for active authentication (16 hex characters)
	Nonce string `json:"nonce" example:"1234567890abcdef"`
}

// handleStartValidatePassport starts a document validation session
// @Summary Start document validation session
// @Description Initializes a new validation session and generates a nonce for active authentication. The nonce should be used to perform active authentication on the document chip. The session ID and nonce must be included in subsequent verification/issuance requests.
// @Tags Session
// @Produce json
// @Success 200 {object} ValidatePassportResponse
// @Failure 500 {string} string "error:internal"
// @Router /start-validation [post]
func handleStartValidatePassport(state *ServerState, w http.ResponseWriter, r *http.Request) {
	defer closeRequestBody(r)

	if !requirePOST(w, r) {
		return
	}

	slog.Info("Received request to start document validation")

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

func HandleRedocRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write(redocHTML); err != nil {
		slog.Error("failed to write redoc html", "error", err)
	}
}

func HandleSwaggerRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if _, err := w.Write(swaggerSpec); err != nil {
		slog.Error("failed to write swagger spec", "error", err)
	}
}

func GenerateSessionId() string {
	sessionId := make([]byte, 16)
	if _, err := rand.Read(sessionId); err != nil {
		slog.Error("failed to generate session ID", "error", err)
		return ""
	}
	return fmt.Sprintf("%x", sessionId)
}

// GenerateNonce Generates a random nonce
func GenerateNonce(i int) (string, error) {
	nonce := make([]byte, i)
	if _, err := rand.Read(nonce); err != nil {
		slog.Error("failed to generate nonce", "error", err)
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	hexString := hex.EncodeToString(nonce)
	return hexString, nil
}

func respondWithErr(w http.ResponseWriter, code int, responseBody string, logMsg string, e error) {
	slog.Error(logMsg, "error", e, "status_code", code, "response_body", responseBody)
	w.WriteHeader(code)
	if _, err := w.Write([]byte(responseBody)); err != nil {
		slog.Error("failed to write body to http response", "error", err)
	}
}

// helpers ------------

func writeStaticJSON(w http.ResponseWriter, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if _, err := w.Write(b); err != nil {
		slog.Error("failed to write body to http response", "error", err)
	}
}

func closeRequestBody(r *http.Request) {
	if err := r.Body.Close(); err != nil {
		slog.Error("failed to close request body", "error", err)
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
		slog.Error("failed to write body to http response", "error", err)
	}
	return nil
}
