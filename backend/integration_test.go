package main

import (
	"encoding/json"
	"fmt"
	"go-passport-issuer/analytics"
	mrtdDoc "go-passport-issuer/document"
	"go-passport-issuer/models"
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

// failingRemoveStorage delegates to an in-memory store for everything except
// RemoveToken, which always fails. It simulates the session-token cleanup failing
// while the handler is producing a success response.
type failingRemoveStorage struct {
	*InMemoryTokenStorage
}

func (s failingRemoveStorage) RemoveToken(sessionId string) error {
	return fmt.Errorf("forced removal failure for %s", sessionId)
}

// TestTokenRemovalFailureKeepsResponseValid ensures that the session-token cleanup
// (now performed before the response is written, see issue #131) is best-effort: a
// RemoveToken failure is only logged and must not corrupt the response, which must
// remain a single valid 200 JSON body.
func TestTokenRemovalFailureKeepsResponseValid(t *testing.T) {
	testCases := []struct {
		name     string
		endpoint string
	}{
		{"Passport", PASSPORT_ISSUE_ENDPOINT},
		{"DrivingLicence", EDL_ISSUE_ENDPOINT},
		{"VerifyPassport", "/api/verify-passport"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			storage := failingRemoveStorage{NewInMemoryTokenStorage()}
			startTestServer(t, storage)

			session, nonce := startValidation(t)
			req := newReq(session, nonce)

			url := fmt.Sprintf(TEST_HOST, tc.endpoint)
			resp, body, _ := postJSON[map[string]any](t, url, req)

			// Cleanup failure must not change the status code.
			mustStatus(t, resp, http.StatusOK, body)

			// Body must remain a single, valid JSON object — no appended error bytes.
			require.Truef(t, json.Valid(body), "response body is not valid JSON: %s", body)
			var decoded map[string]any
			require.NoErrorf(t, json.Unmarshal(body, &decoded), "body: %s", body)
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

func TestPassportActiveAuthRequiredWhenDG15Present(t *testing.T) {
	// The chip advertises an AA key (DG15 present) but the request omits the
	// signature: Active Authentication is mandatory when supported, so this must
	// be rejected rather than issued with activeAuthentication = "No".
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

	authentic, err := DocumentValidatorImpl{}.ActivePassport(req, doc)
	require.ErrorIs(t, err, mrtdDoc.ErrActiveAuthRequired)
	require.False(t, authentic)
}

// Verification no longer consumes the session: the same session (and chip
// read) continues into the issue call, which does. This is what lets the
// Iris flow open a face session at verify and issue against it afterwards.
func TestPassportVerifyKeepsSessionForIssuance(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage)

	session, nonce := startValidation(t)
	req := newReq(session, nonce)

	resp, body, _ := postJSON[map[string]any](t, "http://localhost:8081/api/verify-passport", req)
	mustStatus(t, resp, http.StatusOK, body)

	got, err := storage.RetrieveToken(session)
	require.NoError(t, err)
	require.NotEmpty(t, got)

	// Verify may run again; issuance still works after it and consumes the
	// session, after which nothing does.
	resp, body, _ = postJSON[map[string]any](t, "http://localhost:8081/api/verify-passport", req)
	mustStatus(t, resp, http.StatusOK, body)

	resp, body, _ = postJSON[map[string]any](t, fmt.Sprintf(TEST_HOST, PASSPORT_ISSUE_ENDPOINT), req)
	mustStatus(t, resp, http.StatusOK, body)

	_, err = storage.RetrieveToken(session)
	require.Error(t, err)
	resp, body, _ = postJSON[map[string]any](t, "http://localhost:8081/api/verify-passport", req)
	mustStatus(t, resp, http.StatusBadRequest, body)
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

// The Iris arm end to end: the wallet declares both methods and is assigned
// Iris; verify opens the face session bound to the chip portrait; issuance is
// refused until the verifier reports a pass, then succeeds once and consumes
// the session and the face record.
func TestIrisFlowVerifyThenIssue(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	iris := newFakeIris()
	recorder := &capturingRecorder{}
	// Iris only: with both enabled the draw could land on Regula.
	startTestServer(t, storage, func(s *ServerState) {
		s.faceMethods = policy(off, on, false)
		s.irisClient = iris
		s.irisVerifierPublicUrl = "wss://iris-verifier.example"
		s.recorder = recorder
		s.documentValidator = portraitValidator{portrait: portrait}
	})

	start := startValidationDeclaring(t, &StartValidationRequest{
		FaceVerification: &FaceVerificationDeclaration{Capabilities: []string{"regula", "iris"}},
		Client:           &analytics.Client{Platform: "android", Flavor: "play", AppVersion: "8.3.0"},
	})
	require.NotNil(t, start.FaceVerification)
	require.Equal(t, FaceMethodIris, start.FaceVerification.Method)
	require.Empty(t, start.FaceVerification.FaceApiUrl, "iris announces no Face API")
	req := newReq(start.SessionId, start.Nonce)

	// Verify opens the face session from the authenticated portrait.
	resp, body, verification := postJSON[VerificationResponse](t, "http://localhost:8081/api/verify-passport", req)
	mustStatus(t, resp, http.StatusOK, body)
	require.NotNil(t, verification.FaceSession)
	faceSessionID := verification.FaceSession.FaceSessionId
	require.Equal(t, "wss://iris-verifier.example/stream/"+faceSessionID, verification.FaceSession.StreamUrl)
	require.NotEmpty(t, verification.FaceSession.Token)
	require.Equal(t, []string{portraitSha256Hex(portrait)}, iris.created)

	issueURL := fmt.Sprintf(TEST_HOST, PASSPORT_ISSUE_ENDPOINT)

	// Issuance without the evidence: the self-explanatory body.
	resp, body, _ = postJSON[map[string]any](t, issueURL, req)
	mustStatus(t, resp, http.StatusBadRequest, body)
	require.Contains(t, string(body), "update the Yivi app")

	// Issuance with Regula's evidence on an Iris session: mismatch.
	wrong := req
	wrong.LivenessTransactionId = "txn-1"
	resp, body, _ = postJSON[map[string]any](t, issueURL, wrong)
	mustStatus(t, resp, http.StatusBadRequest, body)
	require.Contains(t, string(body), "assigned method")

	// Issuance while the stream has not completed.
	req.FaceSessionId = faceSessionID
	req.FaceAttempt = 1
	req.FaceDurationMs = 4200
	resp, body, _ = postJSON[map[string]any](t, issueURL, req)
	mustStatus(t, resp, http.StatusBadRequest, body)
	require.Equal(t, faceVerificationFailedBody, string(body))

	// The verifier reports a pass: issuance succeeds, once.
	iris.complete(faceSessionID, true, 0.41)
	resp, body, _ = postJSON[map[string]any](t, issueURL, req)
	mustStatus(t, resp, http.StatusOK, body)
	require.Equal(t, []string{faceSessionID}, iris.deleted)
	_, err := retrieveFaceRecord(storage, faceSessionID)
	require.Error(t, err, "face record consumed")
	_, err = storage.RetrieveToken(start.SessionId)
	require.Error(t, err, "session consumed")

	resp, body, _ = postJSON[map[string]any](t, issueURL, req)
	mustStatus(t, resp, http.StatusBadRequest, body)

	// One assignment and one issuance event per gated attempt, all attributed
	// to Iris with the wallet's labels.
	var assigned, issuances int
	for _, e := range recorder.events {
		require.Equal(t, FaceMethodIris, e.Method)
		require.Equal(t, "play", e.Client.Flavor)
		switch e.Kind {
		case analytics.KindAssigned:
			assigned++
		case analytics.KindIssuance:
			issuances++
		}
	}
	require.Equal(t, 1, assigned)
	require.Equal(t, 4, issuances)
	last := recorder.events[len(recorder.events)-1]
	require.Equal(t, analytics.OutcomePassed, last.Outcome)
	require.InDelta(t, 0.41, *last.Score, 1e-9)
	require.EqualValues(t, 4200, *last.DurationMs)
}

// A face session opened for one document cannot issue another: the issuance
// request's portrait must hash to what the face session was opened with.
func TestIrisFlowRefusesAnotherPortrait(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	iris := newFakeIris()
	validator := &switchingValidator{portrait: portrait}
	startTestServer(t, storage, func(s *ServerState) {
		s.faceMethods = policy(off, on, false)
		s.irisClient = iris
		s.irisVerifierPublicUrl = "wss://iris-verifier.example"
		s.documentValidator = validator
	})

	start := startValidationDeclaring(t, &StartValidationRequest{
		FaceVerification: &FaceVerificationDeclaration{Capabilities: []string{"iris"}},
	})
	req := newReq(start.SessionId, start.Nonce)
	resp, body, verification := postJSON[VerificationResponse](t, "http://localhost:8081/api/verify-passport", req)
	mustStatus(t, resp, http.StatusOK, body)
	iris.complete(verification.FaceSession.FaceSessionId, true, 0.3)

	// The next chip read yields a different portrait.
	validator.portrait = []byte("someone else")
	req.FaceSessionId = verification.FaceSession.FaceSessionId
	resp, body, _ = postJSON[map[string]any](t, fmt.Sprintf(TEST_HOST, PASSPORT_ISSUE_ENDPOINT), req)
	mustStatus(t, resp, http.StatusBadRequest, body)
	require.Equal(t, faceVerificationFailedBody, string(body))
	require.Empty(t, iris.deleted)
}

// switchingValidator lets a test change the portrait between requests.
type switchingValidator struct {
	fakeValidator
	portrait []byte
}

func (v *switchingValidator) PassivePassport(_ models.ValidationRequest, _ *cms.CombinedCertPool) (document.Document, error) {
	var doc document.Document
	doc.Mf.Lds1.Dg2 = &document.DG2{Images: []document.DG2Image{{Image: v.portrait}}}
	return doc, nil
}

// A wallet that declares nothing against an issuer with Regula disabled has no
// method to run: a 400 with the self-explanatory body, before any session is
// stored.
func TestStartValidationNoCandidateMethod(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage, func(s *ServerState) {
		s.faceMethods = policy(off, on, false)
		s.irisClient = newFakeIris()
	})
	resp, body, _ := postJSON[map[string]any](t, "http://localhost:8081/api/start-validation", nil)
	mustStatus(t, resp, http.StatusBadRequest, body)
	require.Contains(t, string(body), "update the Yivi app")
	require.Empty(t, storage.TokenMap)
}
