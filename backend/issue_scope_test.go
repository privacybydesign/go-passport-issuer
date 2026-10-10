package main

import (
	"bytes"
	"encoding/json"
	"go-passport-issuer/models"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/stretchr/testify/require"
)

// scopeRecordingCreator records the scope each issue handler passes on.
type scopeRecordingCreator struct {
	scopes []models.IssuanceScope
}

func (c *scopeRecordingCreator) CreatePassportJwt(_ models.PassportData, scope models.IssuanceScope) (string, error) {
	c.scopes = append(c.scopes, scope)
	return "test-jwt", nil
}

func (c *scopeRecordingCreator) CreateIdCardJwt(_ models.PassportData, scope models.IssuanceScope) (string, error) {
	c.scopes = append(c.scopes, scope)
	return "test-jwt", nil
}

func (c *scopeRecordingCreator) CreateEDLJwt(_ models.EDLData, scope models.IssuanceScope) (string, error) {
	c.scopes = append(c.scopes, scope)
	return "test-jwt", nil
}

// photoValidator returns a passport with a chip portrait, which face
// verification needs to have something to match.
type photoValidator struct{ fakeValidator }

func (photoValidator) PassivePassport(_ models.ValidationRequest, _ *cms.CombinedCertPool) (document.Document, error) {
	var doc document.Document
	doc.Mf.Lds1.Dg2 = &document.DG2{Images: []document.DG2Image{{Image: []byte("portrait")}}}
	return doc, nil
}

type issueEndpoint struct {
	name    string
	handler func(*ServerState, http.ResponseWriter, *http.Request)
}

var issueEndpoints = []issueEndpoint{
	{"passport", handleIssuePassport},
	{"id card", handleIssueIdCard},
	{"driving licence", handleIssueEDL},
}

func newScopeState(creator JwtCreator, ageOffered bool) *ServerState {
	storage := NewInMemoryTokenStorage()
	_ = storage.StoreToken(testSessionId, testNonce)

	return &ServerState{
		tokenStorage:         storage,
		jwtCreators:          AllJwtCreators{Passport: creator, IdCard: creator, DrivingLicence: creator},
		passportCertPool:     &cms.CombinedCertPool{},
		documentValidator:    photoValidator{},
		drivingLicenceParser: fakeEDLParser{},
		converter:            fakeConverter{},
		ageCredentialOffered: ageOffered,
	}
}

func issue(t *testing.T, state *ServerState, handler func(*ServerState, http.ResponseWriter, *http.Request), scope models.IssuanceScope, livenessTransactionId string) *httptest.ResponseRecorder {
	t.Helper()

	request := newReq(testSessionId, testNonce)
	request.Issue = scope
	request.LivenessTransactionId = livenessTransactionId
	body, err := json.Marshal(request)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	handler(state, rec, httptest.NewRequest(http.MethodPost, "/api/issue", bytes.NewReader(body)))
	return rec
}

func TestIssueHandlersPassTheRequestedScope(t *testing.T) {
	scopes := []models.IssuanceScope{"", models.IssueDocument, models.IssueDocumentAndAge, models.IssueAgeOnly}

	for _, endpoint := range issueEndpoints {
		for _, scope := range scopes {
			t.Run(endpoint.name+"/"+string(scope), func(t *testing.T) {
				creator := &scopeRecordingCreator{}
				state := newScopeState(creator, true)

				rec := issue(t, state, endpoint.handler, scope, "")

				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				require.Equal(t, []models.IssuanceScope{scope}, creator.scopes)
			})
		}
	}
}

func TestIssueRejectsAgeScopeWhenAgeCredentialNotOffered(t *testing.T) {
	for _, endpoint := range issueEndpoints {
		for _, scope := range []models.IssuanceScope{models.IssueDocumentAndAge, models.IssueAgeOnly} {
			t.Run(endpoint.name+"/"+string(scope), func(t *testing.T) {
				creator := &scopeRecordingCreator{}
				state := newScopeState(creator, false)

				rec := issue(t, state, endpoint.handler, scope, "")

				require.Equal(t, http.StatusBadRequest, rec.Code)
				require.Empty(t, creator.scopes)
				token, err := state.tokenStorage.RetrieveToken(testSessionId)
				require.NoError(t, err, "a rejected request must not consume the session")
				require.Equal(t, testNonce, token)
			})
		}
	}
}

func TestIssueStillIssuesTheDocumentWhenAgeCredentialNotOffered(t *testing.T) {
	for _, endpoint := range issueEndpoints {
		t.Run(endpoint.name, func(t *testing.T) {
			creator := &scopeRecordingCreator{}

			rec := issue(t, newScopeState(creator, false), endpoint.handler, models.IssueDocument, "")

			require.Equal(t, http.StatusOK, rec.Code)
			require.Equal(t, []models.IssuanceScope{models.IssueDocument}, creator.scopes)
		})
	}
}

func TestIssueRejectsUnknownScope(t *testing.T) {
	for _, endpoint := range issueEndpoints {
		t.Run(endpoint.name, func(t *testing.T) {
			creator := &scopeRecordingCreator{}

			rec := issue(t, newScopeState(creator, true), endpoint.handler, "everything", "")

			require.Equal(t, http.StatusBadRequest, rec.Code)
			require.Empty(t, creator.scopes)
		})
	}
}

func TestAgeOnlyIssuanceStillRequiresFaceMatch(t *testing.T) {
	matching := &fakeFaceClient{
		livenessResp: &LivenessStatus{Confirmed: true},
		matchResp:    &FaceMatchResponse{Matched: true, Similarity: 0.9},
	}
	mismatching := &fakeFaceClient{
		livenessResp: &LivenessStatus{Confirmed: true},
		matchResp:    &FaceMatchResponse{Matched: false, Similarity: 0.1},
	}

	t.Run("no liveness transaction", func(t *testing.T) {
		creator := &scopeRecordingCreator{}
		state := newScopeState(creator, true)
		state.faceVerificationClient = matching

		rec := issue(t, state, handleIssuePassport, models.IssueAgeOnly, "")

		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Contains(t, rec.Body.String(), "face verification required")
		require.Empty(t, creator.scopes)
	})

	t.Run("face does not match", func(t *testing.T) {
		creator := &scopeRecordingCreator{}
		state := newScopeState(creator, true)
		state.faceVerificationClient = mismatching

		rec := issue(t, state, handleIssuePassport, models.IssueAgeOnly, "txn-1")

		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Equal(t, "face verification failed", rec.Body.String())
		require.Empty(t, creator.scopes)
	})

	t.Run("face matches", func(t *testing.T) {
		creator := &scopeRecordingCreator{}
		state := newScopeState(creator, true)
		state.faceVerificationClient = matching

		rec := issue(t, state, handleIssuePassport, models.IssueAgeOnly, "txn-1")

		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.Equal(t, []models.IssuanceScope{models.IssueAgeOnly}, creator.scopes)
	})
}

func TestStartValidationAnnouncesAgeCredential(t *testing.T) {
	offered := startValidationWith(t, &ServerState{tokenStorage: NewInMemoryTokenStorage(), ageCredentialOffered: true})
	require.True(t, offered.AgeCredentialOffered)

	notOffered := startValidationWith(t, &ServerState{tokenStorage: NewInMemoryTokenStorage()})
	require.False(t, notOffered.AgeCredentialOffered)
}
