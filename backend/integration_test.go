package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"go-passport-issuer/models"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/utils"
	"github.com/stretchr/testify/require"
)

// -----------------------------------------------------------------------------
// test variables

var testSessionID = GenerateSessionId()
var badSessionID = "bad-session-id"
var testNonce, _ = GenerateNonce(8)
var badNonce = "bad-nonce"

// -----------------------------------------------------------------------------
// tests

// Test that a valid request results in a successful response and the session is removed from storage
func TestSessionIdRemovedSuccess(t *testing.T) {
	var testStorage = NewInMemoryTokenStorage()

	var testState = &ServerState{
		irmaServerURL: "https://irma.example",
		tokenStorage:  testStorage,
		jwtCreator:    fakeJwtCreator{jwt: "test-jwt"},
		cscaCertPool:  &cms.CombinedCertPool{},
		validator:     fakeValidator{},
		converter:     fakeConverter{},
	}

	// Create and store a session/nonce

	err := testStorage.StoreToken(testSessionID, testNonce)
	require.NoError(t, err)

	reqBody := models.PassportValidationRequest{
		SessionId:  testSessionID,
		Nonce:      testNonce,
		DataGroups: map[string]string{},
		EFSOD:      "00",
	}
	b, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/verify-and-issue", bytes.NewReader(b))
	rr := httptest.NewRecorder()

	// Act: handle the request
	handleIssuePassport(testState, rr, req)

	// Assert: response OK
	require.Equalf(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())

	// Assert: token removed from storage
	_, err = testStorage.RetrieveToken(testSessionID)
	require.Error(t, err)

}

func TestSessionIdRemovedFail_BadNonce(t *testing.T) {
	var testStorage = NewInMemoryTokenStorage()

	var testState = &ServerState{
		irmaServerURL: "https://irma.example",
		tokenStorage:  testStorage,
		jwtCreator:    fakeJwtCreator{jwt: "test-jwt"},
		cscaCertPool:  &cms.CombinedCertPool{},
		validator:     fakeValidator{},
		converter:     fakeConverter{},
	}

	err := testStorage.StoreToken(badSessionID, badNonce)
	require.NoError(t, err)

	reqBody := models.PassportValidationRequest{
		SessionId:  badSessionID,
		Nonce:      testNonce, // mismatch with stored nonce
		DataGroups: map[string]string{},
		EFSOD:      "00",
	}
	b, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/verify-and-issue", bytes.NewReader(b))
	rr := httptest.NewRecorder()

	handleIssuePassport(testState, rr, req)

	require.Equalf(t, http.StatusBadRequest, rr.Code, "body: %s", rr.Body.String())

	// Token should still be present since issuance did not proceed
	got, err := testStorage.RetrieveToken(badSessionID)
	require.NoError(t, err)
	require.Equal(t, badNonce, got)
}

func TestSessionIdRemovedFail_SessionReuse(t *testing.T) {
	var testStorage = NewInMemoryTokenStorage()

	var testState = &ServerState{
		irmaServerURL: "https://irma.example",
		tokenStorage:  testStorage,
		jwtCreator:    fakeJwtCreator{jwt: "test-jwt"},
		cscaCertPool:  &cms.CombinedCertPool{},
		validator:     fakeValidator{},
		converter:     fakeConverter{},
	}

	// Create and store a session/nonce

	err := testStorage.StoreToken(testSessionID, testNonce)
	require.NoError(t, err)

	reqBody := models.PassportValidationRequest{
		SessionId:  testSessionID,
		Nonce:      testNonce,
		DataGroups: map[string]string{},
		EFSOD:      "00",
	}
	b, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/verify-and-issue", bytes.NewReader(b))
	rr := httptest.NewRecorder()

	handleIssuePassport(testState, rr, req)

	// Second verification should fail (fresh request/recorder)
	req2 := httptest.NewRequest(http.MethodPost, "/api/verify-and-issue", bytes.NewReader(b))
	rr2 := httptest.NewRecorder()

	handleIssuePassport(testState, rr2, req2)

	require.Equalf(t, http.StatusInternalServerError, rr2.Code, "body: %s", rr2.Body.String())

}

func TestCompleteFlow(t *testing.T) {

	var testStorage = NewInMemoryTokenStorage()

	var testState = &ServerState{
		irmaServerURL: "https://irma.example",
		tokenStorage:  testStorage,
		jwtCreator:    fakeJwtCreator{jwt: "test-jwt"},
		cscaCertPool:  &cms.CombinedCertPool{},
		validator:     fakeValidator{},
		converter:     fakeConverter{},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/start-validate-passport", nil)
	rr := httptest.NewRecorder()
	handleStartValidatePassport(testState, rr, req)

	var jsonBody map[string]string
	err := json.Unmarshal(rr.Body.Bytes(), &jsonBody)
	gotSessionID := jsonBody["session_id"]
	gotNonce := jsonBody["nonce"]

	require.NoError(t, err)
	require.Contains(t, jsonBody, "session_id")
	require.Contains(t, jsonBody, "nonce")
	t.Logf("start-validate response: %s", jsonBody)

	reqBody := models.PassportValidationRequest{
		SessionId:  gotSessionID,
		Nonce:      gotNonce,
		DataGroups: map[string]string{},
		EFSOD:      "00",
	}
	b, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req2 := httptest.NewRequest(http.MethodPost, "/api/verify-and-issue", bytes.NewReader(b))
	rr2 := httptest.NewRecorder()

	handleIssuePassport(testState, rr2, req2)

	require.Equalf(t, http.StatusOK, rr2.Code, "body: %s", rr2.Body.String())

}

func TestPassiveAuthFail_NoDataGroups(t *testing.T) {
	testStorage := NewInMemoryTokenStorage()
	var testState = &ServerState{
		irmaServerURL: "https://irma.example",
		tokenStorage:  testStorage,
		jwtCreator:    fakeJwtCreator{jwt: "test-jwt"},
		cscaCertPool:  &cms.CombinedCertPool{},
		validator:     passportValidatorImpl{},
		converter:     fakeConverter{},
	}
	noDataGroups := models.PassportValidationRequest{
		SessionId:  testSessionID,
		Nonce:      testNonce,
		DataGroups: map[string]string{},
		EFSOD:      "00",
	}
	// Store session/nonce to pass that validation
	err := testStorage.StoreToken(noDataGroups.SessionId, noDataGroups.Nonce)

	require.NoError(t, err)
	b, err := json.Marshal(noDataGroups)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/verify-and-issue", bytes.NewReader(b))
	rr := httptest.NewRecorder()
	handleIssuePassport(testState, rr, req)
	require.Contains(t, fmt.Sprintf("%s", rr.Body), "no data groups found in passport data")

}

func TestPassiveAuthFail_NoEFSOD(t *testing.T) {
	testStorage := NewInMemoryTokenStorage()
	var testState = &ServerState{
		irmaServerURL: "https://irma.example",
		tokenStorage:  testStorage,
		jwtCreator:    fakeJwtCreator{jwt: "test-jwt"},
		cscaCertPool:  &cms.CombinedCertPool{},
		validator:     passportValidatorImpl{},
		converter:     fakeConverter{},
	}
	noEFSOD := models.PassportValidationRequest{
		SessionId: testSessionID,
		Nonce:     testNonce,
		DataGroups: map[string]string{
			"DG1": "00",
		},
	}
	err := testStorage.StoreToken(noEFSOD.SessionId, noEFSOD.Nonce)

	require.NoError(t, err)
	b, err := json.Marshal(noEFSOD)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/verify-and-issue", bytes.NewReader(b))
	rr := httptest.NewRecorder()
	handleIssuePassport(testState, rr, req)
	require.Contains(t, fmt.Sprintf("%s", rr.Body), "EF_SOD is missing in passport data")

}

func TestPassiveAuthFail_UnsupportedDG(t *testing.T) {
	testStorage := NewInMemoryTokenStorage()
	var testState = &ServerState{
		irmaServerURL: "https://irma.example",
		tokenStorage:  testStorage,
		jwtCreator:    fakeJwtCreator{},
		cscaCertPool:  &cms.CombinedCertPool{},
		validator:     passportValidatorImpl{},
		converter:     fakeConverter{},
	}

	var badDG = models.PassportValidationRequest{
		SessionId: testSessionID,
		Nonce:     testNonce,
		DataGroups: map[string]string{
			"DG99": "00",
		},
		EFSOD: readBinToHex(t, "test-data/EF_SOD.bin"),
	}

	err := testStorage.StoreToken(badDG.SessionId, badDG.Nonce)

	require.NoError(t, err)
	b, err := json.Marshal(badDG)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/verify-and-issue", bytes.NewReader(b))
	rr := httptest.NewRecorder()
	handleIssuePassport(testState, rr, req)
	require.Contains(t, fmt.Sprintf("%s", rr.Body), "unsupported data group: DG99")
}

func TestPassiveAuthFail_CreateDG(t *testing.T) {
	testStorage := NewInMemoryTokenStorage()
	var testState = &ServerState{
		irmaServerURL: "https://irma.example",
		tokenStorage:  testStorage,
		jwtCreator:    fakeJwtCreator{},
		cscaCertPool:  &cms.CombinedCertPool{},
		validator:     passportValidatorImpl{},
		converter:     fakeConverter{},
	}

	var dg = models.PassportValidationRequest{
		SessionId: testSessionID,
		Nonce:     testNonce,
		DataGroups: map[string]string{
			"DG1":  readBinToHex(t, "test-data/EF_DG1.bin"),
			"DG15": readBinToHex(t, "test-data/EF_DG15.bin"),
		},
		EFSOD: readBinToHex(t, "test-data/EF_SOD.bin"),
	}

	err := testStorage.StoreToken(dg.SessionId, dg.Nonce)

	require.NoError(t, err)
	b, err := json.Marshal(dg)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/verify-and-issue", bytes.NewReader(b))
	rr := httptest.NewRecorder()
	handleIssuePassport(testState, rr, req)
	require.Contains(t, fmt.Sprintf("%s", rr.Body), "unexpected error")

}

func TestActiveAuthFail_BadSig(t *testing.T) {
	testStorage := NewInMemoryTokenStorage()
	var testState = &ServerState{
		irmaServerURL: "https://irma.example",
		tokenStorage:  testStorage,
		jwtCreator:    fakeJwtCreator{},
		cscaCertPool:  &cms.CombinedCertPool{},
		validator: validatorFuncs{
			PassiveFn: func(req models.PassportValidationRequest, _ *cms.CombinedCertPool) (document.Document, error) {
				var doc document.Document
				for dg, hexStr := range req.DataGroups {
					b, err := hex.DecodeString(hexStr)
					if err != nil {
						return document.Document{}, err
					}
					switch dg {
					case "DG1":
						doc.Mf.Lds1.Dg1, err = document.NewDG1(b)
						if err != nil {
							return document.Document{}, err
						}
					case "DG15":
						doc.Mf.Lds1.Dg15, err = document.NewDG15(b)
						if err != nil {
							return document.Document{}, err
						}
					}
				}
				return doc, nil
			},
			ActiveFn: passportValidatorImpl{}.Active,
		},
		converter: fakeConverter{},
	}

	var dg = models.PassportValidationRequest{
		SessionId: testSessionID,
		Nonce:     testNonce,
		DataGroups: map[string]string{
			"DG1":  readBinToHex(t, "test-data/EF_DG1.bin"),
			"DG15": readBinToHex(t, "test-data/EF_DG15.bin"),
		},
		ActiveAuthSignature: "00",
	}

	err := testStorage.StoreToken(dg.SessionId, dg.Nonce)

	require.NoError(t, err)
	b, err := json.Marshal(dg)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/verify-and-issue", bytes.NewReader(b))
	rr := httptest.NewRecorder()
	handleIssuePassport(testState, rr, req)
	require.Contains(t, fmt.Sprintf("%s", rr.Body), "failed to validate active authentication signature")

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

type validatorFuncs struct {
	PassiveFn func(models.PassportValidationRequest, *cms.CombinedCertPool) (document.Document, error)
	ActiveFn  func(models.PassportValidationRequest, document.Document) (bool, error)
}

func (v validatorFuncs) Passive(req models.PassportValidationRequest, pool *cms.CombinedCertPool) (document.Document, error) {
	return v.PassiveFn(req, pool)
}
func (v validatorFuncs) Active(req models.PassportValidationRequest, doc document.Document) (bool, error) {
	return v.ActiveFn(req, doc)
}

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
