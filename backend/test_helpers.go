package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go-passport-issuer/document/edl"
	"go-passport-issuer/models"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/stretchr/testify/require"
)

var testConfig = ServerConfig{
	Host:           "localhost",
	Port:           8081,
	UseTls:         false,
	TlsCertPath:    "",
	TlsPrivKeyPath: "",
}

func startTestServer(t *testing.T, storage TokenStorage) *Server {
	t.Helper()

	jwtCreators := AllJwtCreators{
		Passport:       fakeJwtCreator{jwt: "test-jwt"},
		DrivingLicence: fakeJwtCreator{jwt: "test-jwt"},
	}
	testState := &ServerState{
		irmaServerURL:        "https://irma.example",
		tokenStorage:         storage,
		jwtCreators:          jwtCreators,
		passportCertPool:     &cms.CombinedCertPool{},
		documentValidator:    fakeValidator{},
		drivingLicenceParser: fakeEDLParser{},
		converter:            fakeConverter{},
	}

	srv, err := NewServer(testState, testConfig)
	require.NoError(t, err)

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("server error: %v", err)
		}
	}()

	waitUntilHealthy(t, "http://localhost:8081/")
	t.Cleanup(func() {
		if err := srv.Stop(); err != nil {
			t.Logf("error shutting down server: %v", err)
		}
	})
	return srv
}

func waitUntilHealthy(t *testing.T, url string) {
	t.Helper()
	const maxAttempts = 50
	for i := 0; i < maxAttempts; i++ {
		if resp, err := http.Get(url); err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server did not start in time")
}

func postJSON[T any](t *testing.T, url string, payload any) (*http.Response, []byte, *T) {
	t.Helper()

	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		require.NoError(t, err)
		body = bytes.NewBuffer(b)
	}
	resp, err := http.Post(url, "application/json", body)
	require.NoError(t, err)

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var decoded *T
	var v T
	_ = json.Unmarshal(respBody, &v)
	decoded = &v

	return resp, respBody, decoded
}

func mustStatus(t *testing.T, resp *http.Response, want int, body []byte) {
	t.Helper()
	require.Equalf(t, want, resp.StatusCode, "body: %s", body)
}

// start-validation bootstrap
func startValidation(t *testing.T) (sessionID, nonce string) {
	t.Helper()
	type startResp struct {
		SessionID string `json:"session_id"`
		Nonce     string `json:"nonce"`
	}
	resp, body, sr := postJSON[startResp](t, "http://localhost:8081/api/start-validation", nil)
	mustStatus(t, resp, http.StatusOK, body)
	require.NotEmpty(t, sr.SessionID)
	require.NotEmpty(t, sr.Nonce)
	return sr.SessionID, sr.Nonce
}

// Request builders
type reqOpt func(*models.ValidationRequest)

func withDG(name, hexVal string) reqOpt {
	return func(r *models.ValidationRequest) {
		if r.DataGroups == nil {
			r.DataGroups = map[string]string{}
		}
		r.DataGroups[name] = hexVal
	}
}

func withEFSOD(hexVal string) reqOpt {
	return func(r *models.ValidationRequest) { r.EFSOD = hexVal }
}

func withSig(hexVal string) reqOpt {
	return func(r *models.ValidationRequest) { r.ActiveAuthSignature = hexVal }
}

func newReq(sessionId, nonce string, opts ...reqOpt) models.ValidationRequest {
	r := models.ValidationRequest{
		SessionId:  sessionId,
		Nonce:      nonce,
		DataGroups: map[string]string{},
		EFSOD:      "00",
	}
	for _, o := range opts {
		o(&r)
	}
	return r
}

func readBinToHex(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err, "failed to read %s", path)
	return hex.EncodeToString(b)
}

// test doubles

type fakeJwtCreator struct{ jwt string }

func (f fakeJwtCreator) CreatePassportJwt(_ models.PassportData) (string, error) {
	return f.jwt, nil
}

func (f fakeJwtCreator) CreateIdCardJwt(_ models.PassportData) (string, error) {
	return f.jwt, nil
}

func (f fakeJwtCreator) CreateEDLJwt(_ models.EDLData) (string, error) {
	return f.jwt, nil
}

type fakeValidator struct{}

func (v fakeValidator) PassiveEDL(request models.ValidationRequest, pool *cms.CertPool) error {
	return nil
}

func (v fakeValidator) ActiveEDL(request models.ValidationRequest) (bool, error) {
	return true, nil
}

func (fakeValidator) PassivePassport(_ models.ValidationRequest, _ *cms.CombinedCertPool, _ string) (document.Document, error) {
	return document.Document{}, nil
}

func (fakeValidator) ActivePassport(_ models.ValidationRequest, _ document.Document, _ string) (bool, error) {
	return true, nil
}

type fakeConverter struct{}

func (fakeConverter) ToPassportData(_ document.Document, _ bool) (models.PassportData, error) {
	return models.PassportData{DocumentNumber: "X"}, nil
}
func (fakeConverter) ToDrivingLicenceData(_ edl.DrivingLicenceDocument, _ bool) (models.EDLData, error) {
	return models.EDLData{DocumentNumber: "123"}, nil
}

type fakeEDLParser struct{}

func (fakeEDLParser) ParseEDLDocument(map[string]string, string) (*edl.DrivingLicenceDocument, error) {
	return &edl.DrivingLicenceDocument{}, nil
}

var testNonce, _ = GenerateNonce(8)

const testSessionId = "s12345"
