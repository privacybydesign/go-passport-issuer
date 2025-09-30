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
// test variables

var testSessionID = GenerateSessionId()

var testNonce, _ = GenerateNonce(8)

const badNonce = "bad-nonce"

var testConfig = ServerConfig{
	Host:           "localhost",
	Port:           8081,
	UseTls:         false,
	TlsCertPath:    "",
	TlsPrivKeyPath: "",
}

// -----------------------------------------------------------------------------
// tests

func TestSessionIdRemovedSuccess(t *testing.T) {
	testStorage := NewInMemoryTokenStorage()

	testServer := CreateStartTestServer(t, testStorage)
	defer stopServer(t, testServer)

	getSession, err := http.Post("http://localhost:8081/api/start-validation", "application/json", nil)
	require.NoError(t, err)

	getSessionBody, err := io.ReadAll(getSession.Body)
	require.NoError(t, err)

	var jsonBody map[string]string
	err = json.Unmarshal(getSessionBody, &jsonBody)
	require.NoError(t, err)

	sessionID := jsonBody["session_id"]

	reqBody := models.PassportValidationRequest{
		SessionId:  sessionID,
		Nonce:      jsonBody["nonce"],
		DataGroups: map[string]string{},
		EFSOD:      "00",
	}
	b, err := json.Marshal(reqBody)
	require.NoError(t, err)

	verifyResp, err := http.Post("http://localhost:8081/api/verify-passport", "application/json", bytes.NewBuffer(b))
	require.NoError(t, err)

	verifyRespBody, err := io.ReadAll(verifyResp.Body)
	require.NoError(t, err)

	require.Equalf(t, http.StatusOK, verifyResp.StatusCode, "body: %s", verifyRespBody)

	var verifyJSON map[string]any
	err = json.Unmarshal(verifyRespBody, &verifyJSON)
	require.NoError(t, err)
	require.Equal(t, true, verifyJSON["verified"])
	require.Equal(t, true, verifyJSON["active_authentication"])

	storedNonce, err := testStorage.RetrieveToken(sessionID)
	require.NoError(t, err)
	require.Equal(t, jsonBody["nonce"], storedNonce)

	resp, err := http.Post("http://localhost:8081/api/verify-and-issue", "application/json", bytes.NewBuffer(b))
	require.NoError(t, err)

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	require.Equalf(t, http.StatusOK, resp.StatusCode, "body: %s", respBody)

	gotnonce, err := testStorage.RetrieveToken(sessionID)
	// Token should be removed so we expect an error and empty nonce
	require.Error(t, err)
	require.Equal(t, gotnonce, "")

}

func TestSessionIdRemovedFail_BadNonce(t *testing.T) {
	testStorage := NewInMemoryTokenStorage()

	testServer := CreateStartTestServer(t, testStorage)
	defer stopServer(t, testServer)

	err := testStorage.StoreToken(testSessionID, testNonce)
	require.NoError(t, err)

	reqBody := models.PassportValidationRequest{
		SessionId:  testSessionID,
		Nonce:      badNonce, // mismatch with stored nonce
		DataGroups: map[string]string{},
		EFSOD:      "00",
	}
	b, err := json.Marshal(reqBody)
	require.NoError(t, err)

	resp, err := http.Post("http://localhost:8081/api/verify-and-issue", "application/json", bytes.NewBuffer(b))
	require.NoError(t, err)

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	// Should fail with 400 because the nonce does not match the sessionID nonce stored
	require.Equalf(t, http.StatusBadRequest, resp.StatusCode, "body: %s", respBody)

}

func TestVerifyPassportFail_BadNonce(t *testing.T) {
	testStorage := NewInMemoryTokenStorage()

	testServer := CreateStartTestServer(t, testStorage)
	defer stopServer(t, testServer)

	err := testStorage.StoreToken(testSessionID, testNonce)
	require.NoError(t, err)

	reqBody := models.PassportValidationRequest{
		SessionId:  testSessionID,
		Nonce:      badNonce,
		DataGroups: map[string]string{},
		EFSOD:      "00",
	}
	b, err := json.Marshal(reqBody)
	require.NoError(t, err)

	resp, err := http.Post("http://localhost:8081/api/verify-passport", "application/json", bytes.NewBuffer(b))
	require.NoError(t, err)

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equalf(t, http.StatusBadRequest, resp.StatusCode, "body: %s", respBody)
}

func TestSessionIdRemovedFail_SessionReuse(t *testing.T) {
	testStorage := NewInMemoryTokenStorage()

	testServer := CreateStartTestServer(t, testStorage)
	defer stopServer(t, testServer)

	getSession, err := http.Post("http://localhost:8081/api/start-validation", "application/json", nil)
	require.NoError(t, err)

	getSessionBody, err := io.ReadAll(getSession.Body)
	require.NoError(t, err)

	var jsonBody map[string]string
	err = json.Unmarshal(getSessionBody, &jsonBody)
	require.NoError(t, err)

	issueReqBody := models.PassportValidationRequest{
		SessionId:  jsonBody["session_id"],
		Nonce:      jsonBody["nonce"],
		DataGroups: map[string]string{},
		EFSOD:      "00",
	}

	b, err := json.Marshal(issueReqBody)
	require.NoError(t, err)
	resp1, err := http.Post("http://localhost:8081/api/verify-and-issue", "application/json", bytes.NewBuffer(b))
	require.NoError(t, err)

	respBody1, err := io.ReadAll(resp1.Body)
	require.NoError(t, err)
	// First request should succeed with 200
	require.Equalf(t, http.StatusOK, resp1.StatusCode, "body: %s", respBody1)

	resp2, err := http.Post("http://localhost:8081/api/verify-and-issue", "application/json", bytes.NewBuffer(b))
	require.NoError(t, err)

	respBody2, err := io.ReadAll(resp2.Body)
	require.NoError(t, err)
	// Should fail with 500 because the sessionID was already used and removed
	require.Equalf(t, http.StatusInternalServerError, resp2.StatusCode, "body: %s", respBody2)

}

func TestCompleteFlow_HappyPath(t *testing.T) {
	testStorage := NewInMemoryTokenStorage()

	testServer := CreateStartTestServer(t, testStorage)
	defer stopServer(t, testServer)

	// Step 1: start-validate
	resp1, err := http.Post("http://localhost:8081/api/start-validation", "application/json", nil)
	require.NoError(t, err)

	respBody1, err := io.ReadAll(resp1.Body)
	require.NoError(t, err)

	require.Equalf(t, http.StatusOK, resp1.StatusCode, "body: %s", respBody1)

	var jsonBody map[string]string
	err = json.Unmarshal(respBody1, &jsonBody)
	require.NoError(t, err)

	reqBody := models.PassportValidationRequest{
		SessionId:  jsonBody["session_id"],
		Nonce:      jsonBody["nonce"],
		DataGroups: map[string]string{},
		EFSOD:      "00",
	}
	b, err := json.Marshal(reqBody)
	require.NoError(t, err)

	resp2, err := http.Post("http://localhost:8081/api/verify-and-issue", "application/json", bytes.NewBuffer(b))
	require.NoError(t, err)

	respBody2, err := io.ReadAll(resp2.Body)
	require.NoError(t, err)

	require.Equalf(t, http.StatusOK, resp2.StatusCode, "body: %s", respBody2)

}

func TestPassiveAuthFail_NoDataGroups(t *testing.T) {
	cscaCertPool, err := cms.GetDefaultMasterList()
	require.NoError(t, err)

	noDataGroups := models.PassportValidationRequest{
		SessionId:  testSessionID,
		Nonce:      testNonce,
		DataGroups: map[string]string{},
		EFSOD:      "00",
	}

	_, err = passportValidatorImpl{}.Passive(noDataGroups, cscaCertPool)
	require.Errorf(t, err, "no data groups found in passport data")

}

func TestPassiveAuthFail_NoEFSOD(t *testing.T) {

	cscaCertPool, err := cms.GetDefaultMasterList()
	require.NoError(t, err)

	noEFSOD := models.PassportValidationRequest{
		SessionId: testSessionID,
		Nonce:     testNonce,
		DataGroups: map[string]string{
			"DG1": "00",
		},
	}

	_, err = passportValidatorImpl{}.Passive(noEFSOD, cscaCertPool)
	require.Errorf(t, err, "EF_SOD is missing in passport data")

}

func TestPassiveAuthFail_UnsupportedDG(t *testing.T) {
	cscaCertPool, err := cms.GetDefaultMasterList()
	require.NoError(t, err)

	var badDG = models.PassportValidationRequest{
		SessionId: testSessionID,
		Nonce:     testNonce,
		DataGroups: map[string]string{
			"DG99": "00",
		},
		EFSOD: readBinToHex(t, "test-data/EF_SOD.bin"),
	}

	_, err = passportValidatorImpl{}.Passive(badDG, cscaCertPool)
	require.Errorf(t, err, "unsupported data group: DG99")
}

func TestPassiveAuthFail_BadSOD(t *testing.T) {
	cscaCertPool, err := cms.GetDefaultMasterList()
	require.NoError(t, err)

	var badSOD = models.PassportValidationRequest{
		SessionId: testSessionID,
		Nonce:     testNonce,
		DataGroups: map[string]string{
			"DG1": "00",
		},
		EFSOD: "00", // bad SOD
	}

	_, err = passportValidatorImpl{}.Passive(badSOD, cscaCertPool)
	require.Errorf(t, err, "failed to create SOD")

}

func TestPassiveAuthFail_BadDG(t *testing.T) {
	cscaCertPool, err := cms.GetDefaultMasterList()
	require.NoError(t, err)

	var badDG = models.PassportValidationRequest{
		SessionId: testSessionID,
		Nonce:     testNonce,
		DataGroups: map[string]string{
			"DG1": "12",
		},
		EFSOD: readBinToHex(t, "test-data/EF_SOD.bin"),
	}

	_, err = passportValidatorImpl{}.Passive(badDG, cscaCertPool)
	require.Errorf(t, err, "failed to create DG1")

}

func TestActiveAuthFail_BadSig(t *testing.T) {
	var dg = models.PassportValidationRequest{
		SessionId: testSessionID,
		Nonce:     testNonce,
		DataGroups: map[string]string{
			"DG1":  readBinToHex(t, "test-data/EF_DG1.bin"),
			"DG15": readBinToHex(t, "test-data/EF_DG15.bin"),
		},
		EFSOD:               readBinToHex(t, "test-data/EF_SOD.bin"),
		ActiveAuthSignature: "00", // bad signature
	}
	var doc document.Document
	var err error
	doc.Mf.Lds1.Dg1, err = document.NewDG1(utils.HexToBytes(dg.DataGroups["DG1"]))
	require.NoError(t, err)
	doc.Mf.Lds1.Dg15, err = document.NewDG15(utils.HexToBytes(dg.DataGroups["DG15"]))
	require.NoError(t, err)

	_, err = passportValidatorImpl{}.Active(dg, doc)
	require.Errorf(t, err, "failed to validate active authentication signature")

}

func TestActiveAuthSkip_NoDG15(t *testing.T) {

	var dg = models.PassportValidationRequest{
		SessionId: testSessionID,
		Nonce:     testNonce,
		DataGroups: map[string]string{
			"DG1": readBinToHex(t, "test-data/EF_DG1.bin"),
		},
		EFSOD:               readBinToHex(t, "test-data/EF_SOD.bin"),
		ActiveAuthSignature: "00",
	}
	var doc document.Document
	var err error
	doc.Mf.Lds1.Dg1, err = document.NewDG1(utils.HexToBytes(dg.DataGroups["DG1"]))
	require.NoError(t, err)

	isSkipped, err := passportValidatorImpl{}.Active(dg, doc)
	require.NoError(t, err)
	require.False(t, isSkipped)

}

func TestActiveAuthSkip_NoSig(t *testing.T) {
	var dg = models.PassportValidationRequest{
		SessionId: testSessionID,
		Nonce:     testNonce,
		DataGroups: map[string]string{
			"DG1":  readBinToHex(t, "test-data/EF_DG1.bin"),
			"DG15": readBinToHex(t, "test-data/EF_DG15.bin"),
		},
		EFSOD: readBinToHex(t, "test-data/EF_SOD.bin"),
	}
	var doc document.Document
	var err error
	doc.Mf.Lds1.Dg1, err = document.NewDG1(utils.HexToBytes(dg.DataGroups["DG1"]))
	require.NoError(t, err)
	doc.Mf.Lds1.Dg15, err = document.NewDG15(utils.HexToBytes(dg.DataGroups["DG15"]))
	require.NoError(t, err)

	isSkipped, err := passportValidatorImpl{}.Active(dg, doc)
	require.NoError(t, err)
	require.False(t, isSkipped)
}

// -----------------------------------------------------------------------------
// test doubles

type fakeJwtCreator struct{ jwt string }

func (f fakeJwtCreator) CreateJwt(_ models.PassportIssuanceRequest) (string, error) {
	return f.jwt, nil
}

type fakeValidator struct{}

func (fakeValidator) Passive(_ models.PassportValidationRequest, _ *cms.CombinedCertPool) (document.Document, error) {
	return document.Document{}, nil
}

func (fakeValidator) Active(_ models.PassportValidationRequest, _ document.Document) (bool, error) {
	return true, nil
}

// validatorFuncs was unused; remove to satisfy linter.

type fakeConverter struct{}

func (fakeConverter) ToIssuanceRequest(_ document.Document, _ bool) (models.PassportIssuanceRequest, error) {
	return models.PassportIssuanceRequest{DocumentNumber: "X"}, nil
}

// -----------------------------------------------------------------------------
// helpers

// readBinToHex reads a file and returns a hex-encoded string of its contents.
// It fails the test immediately if the file cannot be read.
func readBinToHex(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err, "failed to read %s", path)
	return hex.EncodeToString(b)
}

func CreateStartTestServer(t *testing.T, testStorage TokenStorage) *Server {
	t.Helper()

	testState := &ServerState{
		irmaServerURL: "https://irma.example",
		tokenStorage:  testStorage,
		jwtCreator:    fakeJwtCreator{jwt: "test-jwt"},
		cscaCertPool:  &cms.CombinedCertPool{},
		validator:     fakeValidator{},
		converter:     fakeConverter{},
	}

	srv, err := NewServer(testState, testConfig)
	require.NoError(t, err)

	go func() {
		err := srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			t.Errorf("server error: %v", err)
		}
	}()

	// Wait for server to be ready
	const maxAttempts = 50
	for i := 0; i < maxAttempts; i++ {
		resp, err := http.Get("http://localhost:8081/")
		if err == nil {
			err = resp.Body.Close()
			if err != nil {
				t.Fatalf("error closing response body: %v", err)
			}
			break
		}
		// Wait 50ms before retrying
		time.Sleep(50 * time.Millisecond)
		if i == maxAttempts-1 {
			t.Fatalf("server did not start in time: %v", err)
		}
	}

	return srv

}

func stopServer(t *testing.T, server *Server) {
	err := server.Stop()
	if err != nil {
		t.Logf("error shutting down server: %v", err)
	}
}
