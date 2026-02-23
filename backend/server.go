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
	"go-passport-issuer/models"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gorilla/mux"
)

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
	if os.IsNotExist(err) || fi.IsDir() {
		// file does not exist or path is a directory, serve index.html
		slog.Debug("Serving index.html for path", "path", r.URL.Path)
		http.ServeFile(w, r, filepath.Join(h.staticPath, h.indexPath))
		return
	}

	if err != nil {
		// if we got an error (that wasn't that the file doesn't exist) stating the
		// file, return a 500 internal server error and stop
		slog.Error("Error stating file", "path", path, "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// otherwise, use http.FileServer to serve the static file
	slog.Debug("Serving static file", "path", path)
	http.FileServer(http.Dir(h.staticPath)).ServeHTTP(w, r)
}

func NewServer(state *ServerState, config ServerConfig) (*Server, error) {
	slog.Info("Creating new server", "host", config.Host, "port", config.Port, "tls", config.UseTls)
	router := mux.NewRouter()

	router.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("Health check request received")
		err := json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		if err != nil {
			slog.Error("failed to write body to http response", "error", err)
		}
	})

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

type IssuanceResponse struct {
	Jwt           string `json:"jwt"`
	IrmaServerURL string `json:"irma_server_url"`
}

type VerificationResponse struct {
	AuthenticContent bool                   `json:"authentic_content"`
	AuthenticChip    bool                   `json:"authentic_chip"`
	IsExpired        bool                   `json:"is_expired"`
	FaceMatch        *FaceMatchResult       `json:"face_match,omitempty"` // Optional face verification result
}

type FaceMatchResult struct {
	Matched    bool    `json:"matched"`
	Similarity float64 `json:"similarity"`
}

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

	slog.Debug("Driving license verification completed", "active_auth", activeRes, "session_id", request.SessionId)

	isExpired := doc.Dg1.DateOfExpiry.Before(time.Now())
	slog.Debug("Checking expiry", "is_expired", isExpired, "expiry_date", doc.Dg1.DateOfExpiry)

	// Optional face matching
	var faceMatch *FaceMatchResult
	if request.SelfieImage != "" && doc.Dg6 != nil {
		slog.Info("Performing face verification for driving license")
		// Extract photo from DG6
		pngs, err := doc.Dg6.ConvertToPNG()
		if err == nil && len(pngs) > 0 {
			faceMatch, err = performFaceMatch(state, pngs[0], request.SelfieImage)
			if err != nil {
				slog.Warn("Face matching failed", "error", err)
			} else if faceMatch != nil {
				slog.Debug("Face match completed", "matched", faceMatch.Matched, "similarity", faceMatch.Similarity)
			}
		} else if err != nil {
			slog.Warn("Failed to convert DG6 to PNG", "error", err)
		}
	}

	response := VerificationResponse{
		AuthenticContent: true,
		AuthenticChip:    activeRes,
		IsExpired:        isExpired,
		FaceMatch:        faceMatch,
	}

	if err := writeJSON(w, http.StatusOK, response); err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_MARSHAL, err)
		return
	}

	slog.Info("Driving license verification completed successfully", "session_id", request.SessionId)
	removeSessionToken(w, state.tokenStorage, request.SessionId)

}

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

	slog.Debug("Converting driving license data for issuance", "session_id", request.SessionId)
	issuanceRequest, err := state.converter.ToDrivingLicenceData(*doc, activeRes)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_ISSUANCE_CONVERT, err)
		return
	}

	// Optional face matching before issuance
	if request.SelfieImage != "" && issuanceRequest.Photo != "" {
		slog.Info("Performing face verification before driving license issuance")
		faceMatch, err := performFaceMatch(state, issuanceRequest.Photo, request.SelfieImage)
		if err != nil {
			slog.Warn("Face matching failed during driving license issuance", "error", err)
		} else if faceMatch != nil && !faceMatch.Matched {
			slog.Warn("Face verification failed - similarity below threshold", "similarity", faceMatch.Similarity)
			respondWithErr(w, http.StatusBadRequest, "face verification failed", "face does not match document photo", fmt.Errorf("similarity: %f", faceMatch.Similarity))
			return
		} else if faceMatch != nil {
			slog.Debug("Face verification passed", "similarity", faceMatch.Similarity)
		}
	}

	slog.Debug("Creating driving license JWT", "session_id", request.SessionId)
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

	slog.Info("Driving license issued successfully", "session_id", request.SessionId)
	removeSessionToken(w, state.tokenStorage, request.SessionId)

}

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

	slog.Debug("Passport verification completed", "active_auth", activeAuth, "session_id", request.SessionId)

	passportData, err := state.converter.ToPassportData(doc, activeAuth)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_ISSUANCE_CONVERT, err)
		return
	}

	// check expired
	isExpired := passportData.DateOfExpiry.Before(time.Now())
	slog.Debug("Checking passport expiry", "is_expired", isExpired, "expiry_date", passportData.DateOfExpiry)

	// Optional face matching
	var faceMatch *FaceMatchResult
	if request.SelfieImage != "" && passportData.Photo != "" {
		slog.Info("Performing face verification")
		faceMatch, err = performFaceMatch(state, passportData.Photo, request.SelfieImage)
		if err != nil {
			slog.Warn("Face matching failed", "error", err)
			// Don't fail the entire verification if face matching fails
		} else if faceMatch != nil {
			slog.Debug("Face match completed", "matched", faceMatch.Matched, "similarity", faceMatch.Similarity)
		}
	}

	// set up the response
	response := VerificationResponse{
		AuthenticContent: true,
		AuthenticChip:    activeAuth,
		IsExpired:        isExpired,
		FaceMatch:        faceMatch,
	}

	if err := writeJSON(w, http.StatusOK, response); err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_MARSHAL, err)
		return
	}

	slog.Info("Passport verification completed successfully", "session_id", request.SessionId)
	removeSessionToken(w, state.tokenStorage, request.SessionId)

}

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

	slog.Debug("Converting passport data for ID card issuance", "session_id", request.SessionId)
	issuanceRequest, err := state.converter.ToPassportData(doc, activeAuth)

	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_ISSUANCE_CONVERT, err)
		return
	}

	// Optional face matching before issuance
	if request.SelfieImage != "" && issuanceRequest.Photo != "" {
		slog.Info("Performing face verification before ID card issuance")
		faceMatch, err := performFaceMatch(state, issuanceRequest.Photo, request.SelfieImage)
		if err != nil {
			slog.Warn("Face matching failed during ID card issuance", "error", err)
		} else if faceMatch != nil && !faceMatch.Matched {
			slog.Warn("Face verification failed - similarity below threshold", "similarity", faceMatch.Similarity)
			respondWithErr(w, http.StatusBadRequest, "face verification failed", "face does not match document photo", fmt.Errorf("similarity: %f", faceMatch.Similarity))
			return
		} else if faceMatch != nil {
			slog.Debug("Face verification passed", "similarity", faceMatch.Similarity)
		}
	}

	slog.Debug("Creating ID card JWT", "session_id", request.SessionId)
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

	slog.Info("ID card issued successfully", "session_id", request.SessionId)
	removeSessionToken(w, state.tokenStorage, request.SessionId)
}

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

	slog.Debug("Converting passport data for issuance", "session_id", request.SessionId)
	issuanceRequest, err := state.converter.ToPassportData(doc, activeAuth)

	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_ISSUANCE_CONVERT, err)
		return
	}

	// Optional face matching before issuance
	if request.SelfieImage != "" && issuanceRequest.Photo != "" {
		slog.Info("Performing face verification before passport issuance")
		faceMatch, err := performFaceMatch(state, issuanceRequest.Photo, request.SelfieImage)
		if err != nil {
			slog.Warn("Face matching failed during passport issuance", "error", err)
		} else if faceMatch != nil && !faceMatch.Matched {
			slog.Warn("Face verification failed - similarity below threshold", "similarity", faceMatch.Similarity)
			respondWithErr(w, http.StatusBadRequest, "face verification failed", "face does not match document photo", fmt.Errorf("similarity: %f", faceMatch.Similarity))
			return
		} else if faceMatch != nil {
			slog.Debug("Face verification passed", "similarity", faceMatch.Similarity)
		}
	}

	slog.Debug("Creating passport JWT", "session_id", request.SessionId)
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

	slog.Info("Passport issued successfully", "session_id", request.SessionId)
	removeSessionToken(w, state.tokenStorage, request.SessionId)
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

// removeSessionToken removes token and logs error if failed
func removeSessionToken(w http.ResponseWriter, storage TokenStorage, sessionId string) {
	slog.Debug("Removing session token", "session_id", sessionId)
	if err := storage.RemoveToken(sessionId); err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, ERR_TOKEN_REMOVAL, err)
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

type ValidatePassportResponse struct {
	SessionId string `json:"session_id"`
	Nonce     string `json:"nonce"`
}

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

func respondWithErr(w http.ResponseWriter, code int, responseBody string, logMsg string, e error) {
	slog.Error(logMsg, "error", e, "status_code", code, "response_body", responseBody)
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

// performFaceMatch extracts the document photo and compares it with the provided selfie
func performFaceMatch(state *ServerState, documentPhotoBase64, selfieBase64 string) (*FaceMatchResult, error) {
	slog.Debug("Starting face matching process")

	if state.faceVerificationClient == nil {
		slog.Warn("Face verification client not configured")
		return nil, fmt.Errorf("face verification client not configured")
	}

	if selfieBase64 == "" {
		slog.Debug("No selfie provided, skipping face matching")
		return nil, nil // No selfie provided, skip face matching
	}

	if documentPhotoBase64 == "" {
		slog.Warn("Document photo not available for face matching")
		return nil, fmt.Errorf("document photo not available")
	}

	slog.Debug("Calling face verification client")
	response, err := state.faceVerificationClient.MatchFaces(documentPhotoBase64, selfieBase64)
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

