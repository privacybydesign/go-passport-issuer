package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"go-passport-issuer/models"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/utils"
	"github.com/stretchr/testify/require"
)

// -----------------------------------------------------------------------------
// config

var testConfig = ServerConfig{
	Host:           "localhost",
	Port:           8081,
	UseTls:         false,
	TlsCertPath:    "",
	TlsPrivKeyPath: "",
}

// -----------------------------------------------------------------------------
// helpers

func startTestServer(t *testing.T, storage TokenStorage) *Server {
	t.Helper()

	testState := &ServerState{
		irmaServerURL: "https://irma.example",
		tokenStorage:  storage,
		jwtCreator:    fakeJwtCreator{jwt: "test-jwt"},
		cscaCertPool:  &cms.CombinedCertPool{},
		validator:     fakeValidator{},
		converter:     fakeConverter{},
	}

	srv, err := NewServer(testState, testConfig)
	require.NoError(t, err)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
type reqOpt func(*models.PassportValidationRequest)

func withDG(name, hexVal string) reqOpt {
	return func(r *models.PassportValidationRequest) {
		if r.DataGroups == nil {
			r.DataGroups = map[string]string{}
		}
		r.DataGroups[name] = hexVal
	}
}

func withEFSOD(hexVal string) reqOpt {
	return func(r *models.PassportValidationRequest) { r.EFSOD = hexVal }
}

func withSig(hexVal string) reqOpt {
	return func(r *models.PassportValidationRequest) { r.ActiveAuthSignature = hexVal }
}

func newReq(sessionId, nonce string, opts ...reqOpt) models.PassportValidationRequest {
	r := models.PassportValidationRequest{
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

// -----------------------------------------------------------------------------
// test doubles

type fakeJwtCreator struct{ jwt string }

func (f fakeJwtCreator) CreateJwt(_ models.PassportData) (string, error) { return f.jwt, nil }

type fakeValidator struct{}

func (fakeValidator) Passive(_ models.PassportValidationRequest, _ *cms.CombinedCertPool) (document.Document, error) {
	return document.Document{}, nil
}

func (fakeValidator) Active(_ models.PassportValidationRequest, _ document.Document) (bool, error) {
	return true, nil
}

type fakeConverter struct{}

func (fakeConverter) ToPassportData(_ document.Document, _ bool) (models.PassportData, error) {
	return models.PassportData{DocumentNumber: "X"}, nil
}

var testNonce, _ = GenerateNonce(8)

const testSessionId = "s12345"

// -----------------------------------------------------------------------------
// tests

func TestVerifyAndIssue_Success_RemovesSessionID(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage)

	session, nonce := startValidation(t)
	req := newReq(session, nonce)

	resp, body, _ := postJSON[map[string]any](t, "http://localhost:8081/api/verify-and-issue", req)
	mustStatus(t, resp, http.StatusOK, body)

	got, err := storage.RetrieveToken(session)
	require.Error(t, err)     // removed
	require.Equal(t, "", got) // no token left
}

func TestVerifyAndIssue_Fail_BadNonce(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage)

	session := GenerateSessionId()
	nonce, _ := GenerateNonce(8)
	require.NoError(t, storage.StoreToken(session, nonce))

	req := newReq(session, "bad-nonce")
	resp, body, _ := postJSON[map[string]any](t, "http://localhost:8081/api/verify-and-issue", req)
	mustStatus(t, resp, http.StatusBadRequest, body)
}

func TestVerifyAndIssue_Fail_SessionReuse(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage)

	session, nonce := startValidation(t)
	req := newReq(session, nonce)

	resp1, body1, _ := postJSON[map[string]any](t, "http://localhost:8081/api/verify-and-issue", req)
	mustStatus(t, resp1, http.StatusOK, body1)

	resp2, body2, _ := postJSON[map[string]any](t, "http://localhost:8081/api/verify-and-issue", req)
	mustStatus(t, resp2, http.StatusBadRequest, body2)
}

func TestVerifyAndIssue_Success(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage)

	session, nonce := startValidation(t)
	req := newReq(session, nonce)

	resp, body, _ := postJSON[map[string]any](t, "http://localhost:8081/api/verify-and-issue", req)
	mustStatus(t, resp, http.StatusOK, body)
}

func TestPassiveAuthFail_NoDataGroups(t *testing.T) {
	pool, err := cms.GetDefaultMasterList()
	require.NoError(t, err)

	req := newReq(testSessionId, "n")
	_, err = passportValidatorImpl{}.Passive(req, pool)
	require.Errorf(t, err, "no data groups found in passport data")
}

func TestPassiveAuthFail_NoEFSOD(t *testing.T) {
	pool, err := cms.GetDefaultMasterList()
	require.NoError(t, err)

	req := newReq(testSessionId, "n", withDG("DG1", "00"))
	req.EFSOD = "" // simulate missing
	_, err = passportValidatorImpl{}.Passive(req, pool)
	require.Errorf(t, err, "EF_SOD is missing in passport data")
}

func TestPassiveAuthFail_UnsupportedDG(t *testing.T) {
	pool, err := cms.GetDefaultMasterList()
	require.NoError(t, err)

	req := newReq(testSessionId, "n",
		withDG("DG99", "00"),
		withEFSOD(readBinToHex(t, "test-data/EF_SOD.bin")),
	)
	_, err = passportValidatorImpl{}.Passive(req, pool)
	require.Errorf(t, err, "unsupported data group: DG99")
}

func TestPassiveAuthFail_BadSOD(t *testing.T) {
	certPool, err := cms.GetDefaultMasterList()
	require.NoError(t, err)

	req := newReq(testSessionId, testNonce, withDG("DG1", "00"), withEFSOD("00")) // bad SOD
	_, err = passportValidatorImpl{}.Passive(req, certPool)
	require.Errorf(t, err, "failed to create SOD")
}

func TestPassiveAuthFail_BadDG(t *testing.T) {
	cscaCertPool, err := cms.GetDefaultMasterList()
	require.NoError(t, err)

	req := newReq(testSessionId, testNonce,
		withDG("DG1", "12"), // bad DG1
		withEFSOD(readBinToHex(t, "test-data/EF_SOD.bin")),
	)
	_, err = passportValidatorImpl{}.Passive(req, cscaCertPool)
	require.ErrorContains(t, err, "failed to create DG1")

}

func TestActiveAuthFail_BadSig(t *testing.T) {
	req := newReq(testSessionId, testNonce,
		withDG("DG1", readBinToHex(t, "test-data/EF_DG1.bin")),
		withDG("DG15", readBinToHex(t, "test-data/EF_DG15.bin")),
		withEFSOD(readBinToHex(t, "test-data/EF_SOD.bin")),
		withSig("00"), // bad signature
	)

	var doc document.Document
	var err error
	doc.Mf.Lds1.Dg1, err = document.NewDG1(utils.HexToBytes(req.DataGroups["DG1"]))
	require.NoError(t, err)
	doc.Mf.Lds1.Dg15, err = document.NewDG15(utils.HexToBytes(req.DataGroups["DG15"]))
	require.NoError(t, err)

	_, err = passportValidatorImpl{}.Active(req, doc)
	require.ErrorContains(t, err, "failed to validate active authentication signature")
}

func TestActiveAuthSkip_NoDG15(t *testing.T) {
	req := newReq(testSessionId, testNonce,
		withDG("DG1", readBinToHex(t, "test-data/EF_DG1.bin")),
		withEFSOD(readBinToHex(t, "test-data/EF_SOD.bin")),
		withSig("00"),
	)

	var doc document.Document
	var err error
	doc.Mf.Lds1.Dg1, err = document.NewDG1(utils.HexToBytes(req.DataGroups["DG1"]))
	require.NoError(t, err)

	skipped, err := passportValidatorImpl{}.Active(req, doc)
	require.NoError(t, err)
	require.False(t, skipped)
}

func TestActiveAuthSkip_NoSig(t *testing.T) {
	req := newReq(testSessionId, testNonce,
		withDG("DG1", readBinToHex(t, "test-data/EF_DG1.bin")),
		withDG("DG15", readBinToHex(t, "test-data/EF_DG15.bin")),
		withEFSOD(readBinToHex(t, "test-data/EF_SOD.bin")),
	)

	var doc document.Document
	var err error
	doc.Mf.Lds1.Dg1, err = document.NewDG1(utils.HexToBytes(req.DataGroups["DG1"]))
	require.NoError(t, err)
	doc.Mf.Lds1.Dg15, err = document.NewDG15(utils.HexToBytes(req.DataGroups["DG15"]))
	require.NoError(t, err)

	skipped, err := passportValidatorImpl{}.Active(req, doc)
	require.NoError(t, err)
	require.False(t, skipped)
}

func TestVerifyPassport_Success_RemovesSession(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage)

	session, nonce := startValidation(t)
	req := newReq(session, nonce)

	resp, body, _ := postJSON[map[string]any](t, "http://localhost:8081/api/verify-passport", req)
	mustStatus(t, resp, http.StatusOK, body)

	got, err := storage.RetrieveToken(session)
	require.Error(t, err)
	require.Equal(t, "", got)
}

func TestVerifyPassport_Fail_BadNonce(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage)

	session := GenerateSessionId()
	nonce, _ := GenerateNonce(8)
	require.NoError(t, storage.StoreToken(session, nonce))

	req := newReq(session, "bad-nonce")
	resp, body, _ := postJSON[map[string]any](t, "http://localhost:8081/api/verify-passport", req)
	mustStatus(t, resp, http.StatusBadRequest, body)
}

func TestVerifyPassport_Fail_SessionReuse(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage)

	session, nonce := startValidation(t)
	req := newReq(session, nonce)

	resp1, body1, _ := postJSON[map[string]any](t, "http://localhost:8081/api/verify-passport", req)
	mustStatus(t, resp1, http.StatusOK, body1)

	resp2, body2, _ := postJSON[map[string]any](t, "http://localhost:8081/api/verify-passport", req)
	mustStatus(t, resp2, http.StatusBadRequest, body2)
}
