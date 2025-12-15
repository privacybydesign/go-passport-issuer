package main

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/utils"
	"github.com/stretchr/testify/require"
)

const PASSPORT_ISSUE_ENDPOINT = "/api/issue-passport"
const EDL_ISSUE_ENDPOINT = "/api/issue-driving-licence"
const TEST_HOST = "http://localhost:8081%s"

func TestIssueDocumentSuccessRemovesSessionID(t *testing.T) {
	testCases := []struct {
		name     string
		endpoint string
	}{
		{"Passport", PASSPORT_ISSUE_ENDPOINT},
		{"DrivingLicence", EDL_ISSUE_ENDPOINT},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			storage := NewInMemoryTokenStorage()
			startTestServer(t, storage)

			session, nonce := startValidation(t)
			req := newReq(session, nonce)

			url := fmt.Sprintf(TEST_HOST, tc.endpoint)
			resp, body, _ := postJSON[map[string]any](t, url, req)
			mustStatus(t, resp, http.StatusOK, body)

			got, err := storage.RetrieveToken(session)
			require.Error(t, err)     // removed
			require.Equal(t, "", got) // no token left
		})
	}
}
func TestIssueDocumentFailBadNonce(t *testing.T) {
	testCases := []struct {
		name     string
		endpoint string
	}{
		{"Passport", PASSPORT_ISSUE_ENDPOINT},
		{"DrivingLicence", EDL_ISSUE_ENDPOINT},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			storage := NewInMemoryTokenStorage()
			startTestServer(t, storage)

			session := GenerateSessionId()
			nonce, err := GenerateNonce(8)
			require.NoError(t, err)
			require.NoError(t, storage.StoreToken(session, nonce))

			req := newReq(session, "bad-nonce")
			url := fmt.Sprintf(TEST_HOST, tc.endpoint)
			resp, body, _ := postJSON[map[string]any](t, url, req)
			mustStatus(t, resp, http.StatusBadRequest, body)
		})
	}
}
func TestIssueDocumentFailSessionReuse(t *testing.T) {
	testCases := []struct {
		name     string
		endpoint string
	}{
		{"Passport", PASSPORT_ISSUE_ENDPOINT},
		{"DrivingLicence", EDL_ISSUE_ENDPOINT},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			storage := NewInMemoryTokenStorage()
			startTestServer(t, storage)

			session, nonce := startValidation(t)
			req := newReq(session, nonce)

			url := fmt.Sprintf(TEST_HOST, tc.endpoint)
			resp1, body1, _ := postJSON[map[string]any](t, url, req)
			mustStatus(t, resp1, http.StatusOK, body1)

			resp2, body2, _ := postJSON[map[string]any](t, url, req)
			mustStatus(t, resp2, http.StatusBadRequest, body2)
		})
	}
}
func TestIssueDocumentSuccess(t *testing.T) {
	testCases := []struct {
		name     string
		endpoint string
	}{
		{"Passport", PASSPORT_ISSUE_ENDPOINT},
		{"DrivingLicence", EDL_ISSUE_ENDPOINT},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			storage := NewInMemoryTokenStorage()
			startTestServer(t, storage)

			session, nonce := startValidation(t)
			req := newReq(session, nonce)

			url := fmt.Sprintf(TEST_HOST, tc.endpoint)
			resp, body, _ := postJSON[map[string]any](t, url, req)
			require.Equal(t, 200, resp.StatusCode, body)
			mustStatus(t, resp, http.StatusOK, body)
		})
	}
}

func TestPassportPassiveAuthFailNoDataGroups(t *testing.T) {
	pool, err := cms.DefaultMasterList()
	require.NoError(t, err)

	req := newReq(testSessionId, "n")
	_, err = DocumentValidatorImpl{}.PassivePassport(req, pool)
	require.Errorf(t, err, "no data groups found in passport data")
}

func TestPassportPassiveAuthFailNoEFSOD(t *testing.T) {
	pool, err := cms.DefaultMasterList()
	require.NoError(t, err)

	req := newReq(testSessionId, "n", withDG("DG1", "00"))
	req.EFSOD = "" // simulate missing
	_, err = DocumentValidatorImpl{}.PassivePassport(req, pool)
	require.Errorf(t, err, "EF_SOD is missing in passport data")
}

func TestPassportPassiveAuthFailUnsupportedDG(t *testing.T) {
	pool, err := cms.DefaultMasterList()
	require.NoError(t, err)

	req := newReq(testSessionId, "n",
		withDG("DG99", "00"),
		withEFSOD(readBinToHex(t, "test-data/EF_SOD.bin")),
	)
	_, err = DocumentValidatorImpl{}.PassivePassport(req, pool)
	require.Errorf(t, err, "unsupported data group: DG99")
}

func TestPassportPassiveAuthFailBadSOD(t *testing.T) {
	certPool, err := cms.DefaultMasterList()
	require.NoError(t, err)

	req := newReq(testSessionId, testNonce, withDG("DG1", "00"), withEFSOD("00")) // bad SOD
	_, err = DocumentValidatorImpl{}.PassivePassport(req, certPool)
	require.Errorf(t, err, "failed to create SOD")
}

func TestPassportPassiveAuthFailBadDG(t *testing.T) {
	cscaCertPool, err := cms.DefaultMasterList()
	require.NoError(t, err)

	req := newReq(testSessionId, testNonce,
		withDG("DG1", "12"), // bad DG1
		withEFSOD(readBinToHex(t, "test-data/EF_SOD.bin")),
	)
	_, err = DocumentValidatorImpl{}.PassivePassport(req, cscaCertPool)
	require.ErrorContains(t, err, "failed to create DG1")

}

func TestPassportActiveAuthFailBadSig(t *testing.T) {
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

	_, err = DocumentValidatorImpl{}.ActivePassport(req, doc)
	require.ErrorContains(t, err, "failed to validate active authentication signature")
}

func TestPassportActiveAuthSkipNoDG15(t *testing.T) {
	req := newReq(testSessionId, testNonce,
		withDG("DG1", readBinToHex(t, "test-data/EF_DG1.bin")),
		withEFSOD(readBinToHex(t, "test-data/EF_SOD.bin")),
		withSig("00"),
	)

	var doc document.Document
	var err error
	doc.Mf.Lds1.Dg1, err = document.NewDG1(utils.HexToBytes(req.DataGroups["DG1"]))
	require.NoError(t, err)

	skipped, err := DocumentValidatorImpl{}.ActivePassport(req, doc)
	require.NoError(t, err)
	require.False(t, skipped)
}

func TestPassportActiveAuthSkipNoSig(t *testing.T) {
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

	skipped, err := DocumentValidatorImpl{}.ActivePassport(req, doc)
	require.NoError(t, err)
	require.False(t, skipped)
}

func TestPassportVerifySuccessRemovesSession(t *testing.T) {
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

func TestPassportVerifyFailBadNonce(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage)

	session := GenerateSessionId()
	nonce, err := GenerateNonce(8)
	require.NoError(t, err)
	require.NoError(t, storage.StoreToken(session, nonce))

	req := newReq(session, "bad-nonce")
	resp, body, _ := postJSON[map[string]any](t, "http://localhost:8081/api/verify-passport", req)
	mustStatus(t, resp, http.StatusBadRequest, body)
}

func TestPassportVerifyFailSessionReuse(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage)

	session, nonce := startValidation(t)
	req := newReq(session, nonce)

	resp1, body1, _ := postJSON[map[string]any](t, "http://localhost:8081/api/verify-passport", req)
	mustStatus(t, resp1, http.StatusOK, body1)

	resp2, body2, _ := postJSON[map[string]any](t, "http://localhost:8081/api/verify-passport", req)
	mustStatus(t, resp2, http.StatusBadRequest, body2)
}
