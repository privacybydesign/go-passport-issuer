package main

import (
	"net/http"
	"testing"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/utils"
	"github.com/stretchr/testify/require"
)

func TestIssuePassport_Success_RemovesSessionID(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage)

	session, nonce := startValidation(t)
	req := newReq(session, nonce)

	resp, body, _ := postJSON[map[string]any](t, "http://localhost:8081/api/issue-passport", req)
	mustStatus(t, resp, http.StatusOK, body)

	got, err := storage.RetrieveToken(session)
	require.Error(t, err)     // removed
	require.Equal(t, "", got) // no token left
}

func TestIssuePassport_Fail_BadNonce(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage)

	session := GenerateSessionId()
	nonce, _ := GenerateNonce(8)
	require.NoError(t, storage.StoreToken(session, nonce))

	req := newReq(session, "bad-nonce")
	resp, body, _ := postJSON[map[string]any](t, "http://localhost:8081/api/issue-passport", req)
	mustStatus(t, resp, http.StatusBadRequest, body)
}

func TestIssuePassport_Fail_SessionReuse(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage)

	session, nonce := startValidation(t)
	req := newReq(session, nonce)

	resp1, body1, _ := postJSON[map[string]any](t, "http://localhost:8081/api/issue-passport", req)
	mustStatus(t, resp1, http.StatusOK, body1)

	resp2, body2, _ := postJSON[map[string]any](t, "http://localhost:8081/api/issue-passport", req)
	mustStatus(t, resp2, http.StatusBadRequest, body2)
}

func TestIssuePassport_Success(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage)

	session, nonce := startValidation(t)
	req := newReq(session, nonce)

	resp, body, _ := postJSON[map[string]any](t, "http://localhost:8081/api/issue-passport", req)
	mustStatus(t, resp, http.StatusOK, body)
}

func TestPassiveAuthFail_NoDataGroups(t *testing.T) {
	pool, err := cms.GetDefaultMasterList()
	require.NoError(t, err)

	req := newReq(testSessionId, "n")
	_, err = PassportValidatorImpl{}.Passive(req, pool)
	require.Errorf(t, err, "no data groups found in passport data")
}

func TestPassiveAuthFail_NoEFSOD(t *testing.T) {
	pool, err := cms.GetDefaultMasterList()
	require.NoError(t, err)

	req := newReq(testSessionId, "n", withDG("DG1", "00"))
	req.EFSOD = "" // simulate missing
	_, err = PassportValidatorImpl{}.Passive(req, pool)
	require.Errorf(t, err, "EF_SOD is missing in passport data")
}

func TestPassiveAuthFail_UnsupportedDG(t *testing.T) {
	pool, err := cms.GetDefaultMasterList()
	require.NoError(t, err)

	req := newReq(testSessionId, "n",
		withDG("DG99", "00"),
		withEFSOD(readBinToHex(t, "test-data/EF_SOD.bin")),
	)
	_, err = PassportValidatorImpl{}.Passive(req, pool)
	require.Errorf(t, err, "unsupported data group: DG99")
}

func TestPassiveAuthFail_BadSOD(t *testing.T) {
	certPool, err := cms.GetDefaultMasterList()
	require.NoError(t, err)

	req := newReq(testSessionId, testNonce, withDG("DG1", "00"), withEFSOD("00")) // bad SOD
	_, err = PassportValidatorImpl{}.Passive(req, certPool)
	require.Errorf(t, err, "failed to create SOD")
}

func TestPassiveAuthFail_BadDG(t *testing.T) {
	cscaCertPool, err := cms.GetDefaultMasterList()
	require.NoError(t, err)

	req := newReq(testSessionId, testNonce,
		withDG("DG1", "12"), // bad DG1
		withEFSOD(readBinToHex(t, "test-data/EF_SOD.bin")),
	)
	_, err = PassportValidatorImpl{}.Passive(req, cscaCertPool)
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

	_, err = PassportValidatorImpl{}.Active(req, doc)
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

	skipped, err := PassportValidatorImpl{}.Active(req, doc)
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

	skipped, err := PassportValidatorImpl{}.Active(req, doc)
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
