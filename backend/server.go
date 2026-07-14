package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"go-passport-issuer/document/edl"
	"go-passport-issuer/images"
	"go-passport-issuer/models"

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
	faceVerificationClient FaceVerificationClient
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
		slog.Info("Starting server with TLS", "host", s.config.Host, "port", s.config.Port, "cert", s.config.TlsCertPath, "key", s.config.TlsPrivKeyPath)
		return s.server.ListenAndServeTLS(s.config.TlsCertPath, s.config.TlsPrivKeyPath)
	} else {
		slog.Info("Starting server without TLS", "host", s.config.Host, "port", s.config.Port)
		return s.server.ListenAndServe()
	}
}

func (s *Server) Stop() error {
	slog.Info("Shutting down server")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := s.server.Shutdown(ctx)
	if err != nil {
		slog.Error("Error during server shutdown", "error", err)
	} else {
		slog.Info("Server shut down successfully")
	}
	return err
}

// ServeHTTP inspects the URL path to locate a file within the static dir
// on the SPA handler. If a file is found, it will be served. If not, the
// file located at the index path on the SPA handler will be served. This
// is suitable behavior for serving an SPA (single page application).
// https://github.com/gorilla/mux?tab=readme-ov-file#serving-single-page-applications
func (h SpaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	slog.Debug("SPA handler serving request", "path", r.URL.Path)
	// Join internally call path.Clean to prevent directory traversal
	path := filepath.Join(h.staticPath, r.URL.Path)
	// check whether a file exists or is a directory at the given path
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		// file does not exist, serve index.html
		slog.Debug("Serving index.html for path", "path", r.URL.Path)
		http.ServeFile(w, r, filepath.Join(h.staticPath, h.indexPath))
		return
	}

	if err != nil {
		// if we got an error (that wasn't that the file doesn't exist) stating the
		// file, log it server-side and return a generic 500 so we don't leak
		// filesystem paths or OS internals to the client. This must be checked
		// before dereferencing fi, which is nil whenever os.Stat returns an error.
		slog.Error("static file error", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if fi.IsDir() {
		// path is a directory, serve index.html
		slog.Debug("Serving index.html for directory path", "path", r.URL.Path)
		http.ServeFile(w, r, filepath.Join(h.staticPath, h.indexPath))
		return
	}

	// otherwise, use http.FileServer to serve the static file
	slog.Debug("Serving static file", "path", path)
	http.FileServer(http.Dir(h.staticPath)).ServeHTTP(w, r)
}

func NewServer(state *ServerState, config ServerConfig) (*Server, error) {
	slog.Info("Creating new server", "host", config.Host, "port", config.Port, "tls", config.UseTls)
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

	slog.Debug("Registered all API routes")

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

	slog.Info("Server created successfully", "address", addr)
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
	// Optional face verification result
	FaceMatch *FaceMatchResult `json:"face_match,omitempty"`
}

// FaceMatchResult contains the result of comparing the document chip portrait
// with the live face captured during a Regula liveness session.
type FaceMatchResult struct {
	// True if the document portrait and live face match above the similarity threshold
	Matched bool `json:"matched" example:"true"`
	// Similarity score between the document portrait and live face
	Similarity float64 `json:"similarity" example:"0.92"`
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

	const endpoint = "verify-driving-licence"
	slog.Info("Received request", "endpoint", endpoint)

	doc, request, activeRes, err := VerifyDrivingLicenceRequest(r, state)
	if err != nil {
		respondWithErr(w, http.StatusBadRequest, "invalid request", "failed to verify driving license", err,
			"endpoint", endpoint, "session_id", request.SessionId)
		return
	}

	slog.Debug("Driving license verification completed", "active_auth", activeRes, "session_id", request.SessionId)

	isExpired := doc.Dg1.DateOfExpiry.Before(time.Now())
	slog.Debug("Checking expiry", "is_expired", isExpired, "expiry_date", doc.Dg1.DateOfExpiry)

	// Optional face matching against the live face from the liveness session.
	var faceMatch *FaceMatchResult
	if request.LivenessTransactionId != "" && doc.Dg6 != nil {
		slog.Info("Performing face verification for driving license")
		// Use the original DG6 chip image (not the display PNG) for matching.
		docImage, imgErr := doc.Dg6.RawBase64()
		if imgErr != nil {
			slog.Warn("Failed to extract DG6 image for face matching", "error", imgErr)
		} else {
			faceMatch, err = performFaceMatch(state, docImage, request.LivenessTransactionId)
			if err != nil {
				slog.Warn("Face matching failed", "error", err)
			} else if faceMatch != nil {
				slog.Debug("Face match completed", "matched", faceMatch.Matched, "similarity", faceMatch.Similarity)
			}
		}
	}

	response := VerificationResponse{
		AuthenticContent: true,
		AuthenticChip:    activeRes,
		IsExpired:        isExpired,
		FaceMatch:        faceMatch,
	}

	// Invalidate the one-time session before writing the response so the token
	// cannot be replayed even if the write below fails.
	removeSessionToken(state.tokenStorage, request.SessionId)

	if err := writeJSON(w, http.StatusOK, response); err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_MARSHAL, err)
		return
	}

	slog.Info("Driving license verification completed successfully", "session_id", request.SessionId)
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

	const endpoint = "issue-driving-licence"
	slog.Info("Received request", "endpoint", endpoint)
	doc, request, activeRes, err := VerifyDrivingLicenceRequest(r, state)

	if err != nil {
		respondWithErr(w, http.StatusBadRequest, "invalid request", "failed to verify driving licence", err,
			"endpoint", endpoint, "session_id", request.SessionId)
		return
	}

	slog.Debug("Converting driving license data for issuance", "session_id", request.SessionId)
	issuanceRequest, err := state.converter.ToDrivingLicenceData(*doc, activeRes)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_ISSUANCE_CONVERT, err)
		return
	}

	// Face verification before issuance (fail-closed when Regula is configured).
	// Uses the original DG6 chip image (not the display PNG) for matching.
	var edlImage string
	if doc.Dg6 != nil {
		if img, imgErr := doc.Dg6.RawBase64(); imgErr != nil {
			slog.Warn("Failed to extract DG6 image for face matching", "error", imgErr)
		} else {
			edlImage = img
		}
	}
	if !verifyFaceBeforeIssuance(state, w, edlImage, request.LivenessTransactionId, "driving-licence") {
		return
	}

	slog.Debug("Creating driving license JWT", "session_id", request.SessionId)
	jwt, err := state.jwtCreators.DrivingLicence.CreateEDLJwt(issuanceRequest)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ERR_JWT_CREATION, ERR_JWT_CREATION, err)
		return
	}

	if !writeIssuanceResponse(state, w, jwt, request.SessionId) {
		return
	}

	slog.Info("Driving license issued successfully", "session_id", request.SessionId)
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

	const endpoint = "verify-passport"
	slog.Info("Received request", "endpoint", endpoint)

	doc, activeAuth, request, err := VerifyPassportRequest(r, state)
	if err != nil {
		respondWithErr(w, http.StatusBadRequest, "invalid request", ERR_PASSPORT_VERIFICATION, err,
			"endpoint", endpoint, "session_id", request.SessionId)
		return
	}

	slog.Debug("Passport verification completed", "active_auth", activeAuth, "session_id", request.SessionId)

	passportData, err := state.converter.ToPassportData(doc, activeAuth)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_ISSUANCE_CONVERT, err)
		return
	}

	// check expired
	isExpired := passportData.DateOfExpiry.Before(time.Now())
	slog.Debug("Checking passport expiry", "is_expired", isExpired, "expiry_date", passportData.DateOfExpiry)

	// Optional face matching against the live face from the liveness session.
	var faceMatch *FaceMatchResult
	if request.LivenessTransactionId != "" {
		slog.Info("Performing face verification")
		// Use the original DG2 chip image (not the display PNG) for matching.
		docImage, imgErr := images.RawDG2ImageBase64(doc.Mf.Lds1.Dg2)
		if imgErr != nil {
			slog.Warn("Failed to extract DG2 image for face matching", "error", imgErr)
		} else {
			faceMatch, err = performFaceMatch(state, docImage, request.LivenessTransactionId)
			if err != nil {
				slog.Warn("Face matching failed", "error", err)
				// Don't fail the entire verification if face matching fails
			} else if faceMatch != nil {
				slog.Debug("Face match completed", "matched", faceMatch.Matched, "similarity", faceMatch.Similarity)
			}
		}
	}

	// set up the response
	response := VerificationResponse{
		AuthenticContent: true,
		AuthenticChip:    activeAuth,
		IsExpired:        isExpired,
		FaceMatch:        faceMatch,
	}

	// Invalidate the one-time session before writing the response so the token
	// cannot be replayed even if the write below fails.
	removeSessionToken(state.tokenStorage, request.SessionId)

	if err := writeJSON(w, http.StatusOK, response); err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_MARSHAL, err)
		return
	}

	slog.Info("Passport verification completed successfully", "session_id", request.SessionId)
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

	const endpoint = "issue-id-card"
	slog.Info("Received request", "endpoint", endpoint)

	doc, activeAuth, request, err := VerifyPassportRequest(r, state)
	if err != nil {
		respondWithErr(w, http.StatusBadRequest, "invalid request", ERR_PASSPORT_VERIFICATION, err,
			"endpoint", endpoint, "session_id", request.SessionId)
		return
	}

	slog.Debug("Converting passport data for ID card issuance", "session_id", request.SessionId)
	issuanceRequest, err := state.converter.ToPassportData(doc, activeAuth)

	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_ISSUANCE_CONVERT, err)
		return
	}

	// Face verification before issuance (fail-closed when Regula is configured).
	// Uses the original DG2 chip image (not the display PNG) for matching.
	idCardImage, imgErr := images.RawDG2ImageBase64(doc.Mf.Lds1.Dg2)
	if imgErr != nil {
		slog.Warn("Failed to extract DG2 image for face matching", "error", imgErr)
	}
	if !verifyFaceBeforeIssuance(state, w, idCardImage, request.LivenessTransactionId, "id-card") {
		return
	}

	slog.Debug("Creating ID card JWT", "session_id", request.SessionId)
	jwt, err := state.jwtCreators.IdCard.CreateIdCardJwt(issuanceRequest)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ERR_JWT_CREATION, ERR_JWT_CREATION, err)
		return
	}

	if !writeIssuanceResponse(state, w, jwt, request.SessionId) {
		return
	}

	slog.Info("ID card issued successfully", "session_id", request.SessionId)
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

	const endpoint = "issue-passport"
	slog.Info("Received request", "endpoint", endpoint)

	doc, activeAuth, request, err := VerifyPassportRequest(r, state)
	if err != nil {
		respondWithErr(w, http.StatusBadRequest, "invalid request", ERR_PASSPORT_VERIFICATION, err,
			"endpoint", endpoint, "session_id", request.SessionId)
		return
	}

	slog.Debug("Converting passport data for issuance", "session_id", request.SessionId)
	issuanceRequest, err := state.converter.ToPassportData(doc, activeAuth)

	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_ISSUANCE_CONVERT, err)
		return
	}

	// Face verification before issuance (fail-closed when Regula is configured).
	// Uses the original DG2 chip image (not the display PNG) for matching.
	passportImage, imgErr := images.RawDG2ImageBase64(doc.Mf.Lds1.Dg2)
	if imgErr != nil {
		slog.Warn("Failed to extract DG2 image for face matching", "error", imgErr)
	}
	if !verifyFaceBeforeIssuance(state, w, passportImage, request.LivenessTransactionId, "passport") {
		return
	}

	slog.Debug("Creating passport JWT", "session_id", request.SessionId)
	jwt, err := state.jwtCreators.Passport.CreatePassportJwt(issuanceRequest)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ERR_JWT_CREATION, ERR_JWT_CREATION, err)
		return
	}

	if !writeIssuanceResponse(state, w, jwt, request.SessionId) {
		return
	}

	slog.Info("Passport issued successfully", "session_id", request.SessionId)
}

func VerifyPassportRequest(r *http.Request, state *ServerState) (document.Document, bool, models.ValidationRequest, error) {
	slog.Debug("Starting passport verification request processing")

	request, err := decodeValidationRequest(r)
	if err != nil {
		return document.Document{}, false, request, err
	}

	slog.Debug("Validating session", "session_id", request.SessionId)
	if err := validateSession(state.tokenStorage, request.SessionId, request.Nonce); err != nil {
		return document.Document{}, false, request, err
	}

	slog.Debug("Performing passive authentication", "session_id", request.SessionId)
	var doc document.Document
	doc, err = state.documentValidator.PassivePassport(request, state.passportCertPool)
	if err != nil {
		return document.Document{}, false, request, fmt.Errorf("%s: %w", ERR_PASSIVE_FAILED, err)
	}

	slog.Debug("Passive authentication successful, performing active authentication", "session_id", request.SessionId)
	activeAuth, err := state.documentValidator.ActivePassport(request, doc)
	if err != nil {
		return document.Document{}, false, request, fmt.Errorf("%s: %w", ERR_ACTIVE_FAILED, err)
	}

	slog.Debug("Active authentication completed", "session_id", request.SessionId, "result", activeAuth)
	return doc, activeAuth, request, nil
}

func VerifyDrivingLicenceRequest(r *http.Request, state *ServerState) (doc *edl.DrivingLicenceDocument, request models.ValidationRequest, activeRes bool, err error) {
	slog.Debug("Starting driving license verification request processing")

	request, err = decodeValidationRequest(r)
	if err != nil {
		return doc, request, false, err
	}

	slog.Debug("Validating session", "session_id", request.SessionId)
	if err := validateSession(state.tokenStorage, request.SessionId, request.Nonce); err != nil {
		return doc, request, false, err
	}

	slog.Debug("Performing passive authentication for driving license", "session_id", request.SessionId)
	err = state.documentValidator.PassiveEDL(request, state.drivingLicenceCertPool)
	if err != nil {
		return doc, request, false, fmt.Errorf("%s: %w", ERR_PASSIVE_FAILED, err)
	}

	slog.Debug("Passive authentication successful, performing active authentication", "session_id", request.SessionId)
	result, err := state.documentValidator.ActiveEDL(request)
	if err != nil {
		return doc, request, false, fmt.Errorf("%s: %w", ERR_ACTIVE_FAILED, err)
	}

	slog.Debug("Active authentication completed, parsing EDL document", "session_id", request.SessionId, "result", result)
	doc, err = state.drivingLicenceParser.ParseEDLDocument(request.DataGroups, request.EFSOD)
	if err != nil {
		return doc, request, false, fmt.Errorf("failed to parse EDL document: %w", err)
	}
	slog.Debug("EDL document parsed successfully", "session_id", request.SessionId)
	return doc, request, result, nil
}

// -----------------------------------------------------------------------------------

// validateSession validates session and nonce
func validateSession(storage TokenStorage, sessionId, nonce string) error {
	slog.Debug("Validating session and nonce", "session_id", sessionId)
	storedNonce, err := storage.RetrieveToken(sessionId)
	if err != nil {
		slog.Warn("Failed to retrieve token from storage", "session_id", sessionId, "error", err)
		return fmt.Errorf("%s: %w", ERR_TOKEN_RETRIEVAL, err)
	}

	if storedNonce == "" || storedNonce != nonce {
		slog.Warn("Invalid nonce or session", "session_id", sessionId, "nonce_empty", storedNonce == "", "nonce_match", storedNonce == nonce)
		return fmt.Errorf("%s", ERR_INVALID_NONCE_SESSION)
	}

	slog.Debug("Session validation successful", "session_id", sessionId)
	return nil
}

// removeSessionToken invalidates the one-time session token, logging an error if
// removal fails. It is invoked before the response is written so that a validated
// session is always consumed even if the subsequent write fails. Removal is
// best-effort: a failure must not alter the response, so it is only logged (never
// written back to the client).
func removeSessionToken(storage TokenStorage, sessionId string) {
	slog.Debug("Removing session token", "session_id", sessionId)
	if err := storage.RemoveToken(sessionId); err != nil {
		slog.Error(ERR_TOKEN_REMOVAL, "error", err, "session_id", sessionId)
	} else {
		slog.Debug("Session token removed successfully", "session_id", sessionId)
	}
}

// decodeValidationRequest decodes the request body
func decodeValidationRequest(r *http.Request) (models.ValidationRequest, error) {
	slog.Debug("Decoding validation request body")
	var request models.ValidationRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		slog.Warn("Failed to decode validation request", "error", err)
		return request, fmt.Errorf("decode request body: %w", err)
	}
	slog.Debug("Validation request decoded successfully", "session_id", request.SessionId)
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
	slog.Debug("Generating session ID")
	sessionId := GenerateSessionId()
	if sessionId == "" {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to generate session ID", fmt.Errorf("failed to generate session ID"))
		return
	}
	slog.Debug("Session ID generated", "session_id", sessionId)

	// Generate an 8 byte nonce
	slog.Debug("Generating nonce", "session_id", sessionId)
	nonce, err := GenerateNonce(8)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to generate nonce", err)
		return
	}
	slog.Debug("Nonce generated", "session_id", sessionId)

	// Store the nonce in Redis, should be removed when the jwt is handed over to the app
	slog.Debug("Storing nonce in token storage", "session_id", sessionId)
	err = state.tokenStorage.StoreToken(sessionId, nonce)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to store nonce", err)
		return
	}
	slog.Debug("Nonce stored successfully", "session_id", sessionId)

	response := ValidatePassportResponse{
		SessionId: sessionId,
		Nonce:     string(nonce),
	}

	if err := writeJSON(w, http.StatusOK, response); err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_MARSHAL, err)
		return
	}

	slog.Info("Document validation started successfully", "session_id", sessionId)

}

//go:embed associations/android_asset_links.json
var assetlinksJson []byte

func HandleAssetLinksRequest(w http.ResponseWriter, r *http.Request) {
	slog.Debug("Serving Android asset links")
	writeStaticJSON(w, assetlinksJson)
}

//go:embed associations/apple-app-site-association.json
var appleAssociationJson []byte

func HandleAssaRequest(w http.ResponseWriter, r *http.Request) {
	slog.Debug("Serving Apple app site association")
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
	hexId := fmt.Sprintf("%x", sessionId)
	slog.Debug("Session ID generated successfully", "session_id", hexId)
	return hexId
}

// GenerateNonce Generates a random nonce
func GenerateNonce(i int) (string, error) {
	nonce := make([]byte, i)
	if _, err := rand.Read(nonce); err != nil {
		slog.Error("failed to generate nonce", "error", err)
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	hexString := hex.EncodeToString(nonce)
	slog.Debug("Nonce generated successfully", "length", i)
	return hexString, nil
}

func respondWithErr(w http.ResponseWriter, code int, responseBody string, logMsg string, e error, extras ...any) {
	args := []any{"error", e, "status_code", code, "response_body", responseBody}
	args = append(args, extras...)
	slog.Error(logMsg, args...)
	w.WriteHeader(code)
	if _, err := w.Write([]byte(responseBody)); err != nil {
		slog.Error("failed to write body to http response", "error", err)
	}
}

// helpers ------------

func writeStaticJSON(w http.ResponseWriter, b []byte) {
	slog.Debug("Writing static JSON", "size", len(b))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if _, err := w.Write(b); err != nil {
		slog.Error("failed to write body to http response", "error", err)
	} else {
		slog.Debug("Static JSON written successfully", "size", len(b))
	}
}

func closeRequestBody(r *http.Request) {
	if err := r.Body.Close(); err != nil {
		slog.Error("failed to close request body", "error", err)
	}

}

func requirePOST(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		slog.Debug("Non-POST request rejected", "method", r.Method, "path", r.URL.Path)
		respondWithErr(w, http.StatusMethodNotAllowed, "method not allowed", "invalid method", nil)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) error {
	slog.Debug("Writing JSON response", "status_code", status)
	payload, err := json.Marshal(v)
	if err != nil {
		slog.Error("Failed to marshal JSON payload", "error", err)
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, err = w.Write(payload)
	if err != nil {
		slog.Error("failed to write body to http response", "error", err)
	} else {
		slog.Debug("JSON response written successfully", "status_code", status, "payload_size", len(payload))
	}
	return nil
}

// Face verification helpers

// performFaceMatch compares the document chip portrait with the live face
// captured during a Regula liveness session. It confirms the liveness verdict
// server-side before matching, and always deletes the liveness transaction
// afterwards so biometric session data is not retained. It returns nil (with no
// error) when no liveness transaction is provided, meaning matching is skipped.
func performFaceMatch(state *ServerState, documentImageBase64, livenessTransactionID string) (*FaceMatchResult, error) {
	slog.Debug("Starting face matching process")

	if state.faceVerificationClient == nil {
		slog.Warn("Face verification client not configured")
		return nil, fmt.Errorf("face verification client not configured")
	}

	if livenessTransactionID == "" {
		slog.Debug("No liveness transaction provided, skipping face matching")
		return nil, nil // No liveness transaction, skip face matching
	}

	// Regula stores the live portrait and session video against the transaction;
	// remove it once we are done regardless of the outcome (data retention/GDPR).
	// Registered before the checks below so the transaction is always cleaned up
	// on every path that has a transaction ID, even when matching cannot proceed.
	defer func() {
		if err := state.faceVerificationClient.DeleteLivenessTransaction(livenessTransactionID); err != nil {
			slog.Warn("Failed to delete liveness transaction", "error", err)
		}
	}()

	if documentImageBase64 == "" {
		slog.Warn("Document photo not available for face matching")
		return nil, fmt.Errorf("document photo not available")
	}

	// Confirm the liveness verdict server-side before trusting the transaction.
	slog.Debug("Confirming liveness status")
	status, err := state.faceVerificationClient.GetLivenessStatus(livenessTransactionID)
	if err != nil {
		slog.Error("Liveness status check failed", "error", err)
		return nil, fmt.Errorf("failed to retrieve liveness status: %w", err)
	}
	if !status.Confirmed {
		slog.Warn("Liveness not confirmed", "code", status.Code)
		return nil, fmt.Errorf("liveness not confirmed (code %d)", status.Code)
	}

	slog.Debug("Calling face verification client")
	response, err := state.faceVerificationClient.MatchFaceWithLiveness(documentImageBase64, livenessTransactionID)
	if err != nil {
		slog.Error("Face matching call failed", "error", err)
		return nil, fmt.Errorf("face matching failed: %w", err)
	}

	slog.Info("Face matching completed", "matched", response.Matched, "similarity", response.Similarity)
	return &FaceMatchResult{
		Matched:    response.Matched,
		Similarity: response.Similarity,
	}, nil
}

// verifyFaceBeforeIssuance performs face matching before credential issuance.
// Face verification is a feature flag: when Regula is not configured
// (state.faceVerificationClient is nil) it is disabled and issuance proceeds.
// When it is configured, verification is fail-closed — issuance is rejected
// (after writing an error response) unless a confirmed liveness transaction is
// provided and the live face matches the document portrait above the threshold.
// It returns true when issuance may proceed.
func verifyFaceBeforeIssuance(state *ServerState, w http.ResponseWriter, documentImage, livenessTransactionID, documentType string) bool {
	if state.faceVerificationClient == nil {
		slog.Debug("Face verification disabled, skipping", "document_type", documentType)
		return true
	}

	if livenessTransactionID == "" {
		slog.Warn("Liveness transaction required for issuance", "document_type", documentType)
		respondWithErr(w, http.StatusBadRequest, "face verification required", "no liveness transaction provided for issuance", nil, "document_type", documentType)
		return false
	}

	slog.Info("Performing face verification before issuance", "document_type", documentType)
	faceMatch, err := performFaceMatch(state, documentImage, livenessTransactionID)
	if err != nil {
		slog.Warn("Face verification failed during issuance", "document_type", documentType, "error", err)
		respondWithErr(w, http.StatusBadRequest, "face verification failed", "face verification error during issuance", err, "document_type", documentType)
		return false
	}

	if faceMatch == nil || !faceMatch.Matched {
		similarity := 0.0
		if faceMatch != nil {
			similarity = faceMatch.Similarity
		}
		slog.Warn("Face verification failed - similarity below threshold", "similarity", similarity)
		respondWithErr(w, http.StatusBadRequest, "face verification failed", "face does not match document photo", fmt.Errorf("similarity: %f", similarity))
		return false
	}

	slog.Debug("Face verification passed", "similarity", faceMatch.Similarity)
	return true
}

// writeIssuanceResponse invalidates the one-time session token and writes the
// issuance response. The token is removed before the write so a validated
// session is always consumed even if the write fails. It returns false (after
// writing an error response) when marshalling the response fails.
func writeIssuanceResponse(state *ServerState, w http.ResponseWriter, jwt, sessionId string) bool {
	response := IssuanceResponse{
		Jwt:           jwt,
		IrmaServerURL: state.irmaServerURL,
	}

	// Invalidate the one-time session before writing the response so the token
	// cannot be replayed even if the write below fails.
	removeSessionToken(state.tokenStorage, sessionId)

	if err := writeJSON(w, http.StatusOK, response); err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_MARSHAL, err)
		return false
	}
	return true
}
