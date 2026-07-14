package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeFaceClient is a configurable test double for FaceVerificationClient.
type fakeFaceClient struct {
	matchResp    *FaceMatchResponse
	matchErr     error
	livenessResp *LivenessStatus
	livenessErr  error
	deleteErr    error
	deleteCalled bool
	healthErr    error
}

func (f *fakeFaceClient) MatchFaceWithLiveness(_, _ string) (*FaceMatchResponse, error) {
	return f.matchResp, f.matchErr
}

func (f *fakeFaceClient) GetLivenessStatus(_ string) (*LivenessStatus, error) {
	return f.livenessResp, f.livenessErr
}

func (f *fakeFaceClient) DeleteLivenessTransaction(_ string) error {
	f.deleteCalled = true
	return f.deleteErr
}

func (f *fakeFaceClient) HealthCheck() error { return f.healthErr }

func TestPerformFaceMatch_ClientNotConfigured(t *testing.T) {
	state := &ServerState{}
	result, err := performFaceMatch(state, "img", "txn-1")
	require.Error(t, err)
	require.Nil(t, result)
}

func TestPerformFaceMatch_NoLivenessTransactionSkips(t *testing.T) {
	state := &ServerState{faceVerificationClient: &fakeFaceClient{}}
	result, err := performFaceMatch(state, "img", "")
	require.NoError(t, err)
	require.Nil(t, result)
}

func TestPerformFaceMatch_MissingDocumentImage(t *testing.T) {
	fake := &fakeFaceClient{}
	state := &ServerState{faceVerificationClient: fake}
	result, err := performFaceMatch(state, "", "txn-1")
	require.Error(t, err)
	require.Nil(t, result)
	// The liveness transaction must still be deleted for retention/GDPR even
	// when the document image is missing and matching cannot proceed.
	require.True(t, fake.deleteCalled, "liveness transaction must be deleted when a transaction ID is supplied")
}

func TestPerformFaceMatch_LivenessStatusError(t *testing.T) {
	fake := &fakeFaceClient{livenessErr: errors.New("boom")}
	state := &ServerState{faceVerificationClient: fake}
	result, err := performFaceMatch(state, "img", "txn-1")
	require.Error(t, err)
	require.Nil(t, result)
	require.True(t, fake.deleteCalled, "liveness transaction must be deleted even on error")
}

func TestPerformFaceMatch_LivenessNotConfirmed(t *testing.T) {
	fake := &fakeFaceClient{livenessResp: &LivenessStatus{Confirmed: false, Code: 42}}
	state := &ServerState{faceVerificationClient: fake}
	result, err := performFaceMatch(state, "img", "txn-1")
	require.Error(t, err)
	require.Nil(t, result)
	require.True(t, fake.deleteCalled)
}

func TestPerformFaceMatch_MatchError(t *testing.T) {
	fake := &fakeFaceClient{
		livenessResp: &LivenessStatus{Confirmed: true},
		matchErr:     errors.New("match failed"),
	}
	state := &ServerState{faceVerificationClient: fake}
	result, err := performFaceMatch(state, "img", "txn-1")
	require.Error(t, err)
	require.Nil(t, result)
	require.True(t, fake.deleteCalled)
}

func TestPerformFaceMatch_Success(t *testing.T) {
	fake := &fakeFaceClient{
		livenessResp: &LivenessStatus{Confirmed: true},
		matchResp:    &FaceMatchResponse{Matched: true, Similarity: 0.9},
	}
	state := &ServerState{faceVerificationClient: fake}
	result, err := performFaceMatch(state, "img", "txn-1")
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.Matched)
	require.Equal(t, 0.9, result.Similarity)
	require.True(t, fake.deleteCalled)
}

func TestVerifyFaceBeforeIssuance_Disabled(t *testing.T) {
	state := &ServerState{}
	rec := httptest.NewRecorder()
	ok := verifyFaceBeforeIssuance(state, rec, "img", "txn-1", "passport")
	require.True(t, ok)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestVerifyFaceBeforeIssuance_MissingLivenessTransaction(t *testing.T) {
	state := &ServerState{faceVerificationClient: &fakeFaceClient{}}
	rec := httptest.NewRecorder()
	ok := verifyFaceBeforeIssuance(state, rec, "img", "", "passport")
	require.False(t, ok)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestVerifyFaceBeforeIssuance_MatchError(t *testing.T) {
	fake := &fakeFaceClient{livenessErr: errors.New("boom")}
	state := &ServerState{faceVerificationClient: fake}
	rec := httptest.NewRecorder()
	ok := verifyFaceBeforeIssuance(state, rec, "img", "txn-1", "passport")
	require.False(t, ok)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestVerifyFaceBeforeIssuance_NotMatched(t *testing.T) {
	fake := &fakeFaceClient{
		livenessResp: &LivenessStatus{Confirmed: true},
		matchResp:    &FaceMatchResponse{Matched: false, Similarity: 0.1},
	}
	state := &ServerState{faceVerificationClient: fake}
	rec := httptest.NewRecorder()
	ok := verifyFaceBeforeIssuance(state, rec, "img", "txn-1", "passport")
	require.False(t, ok)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestVerifyFaceBeforeIssuance_Passes(t *testing.T) {
	fake := &fakeFaceClient{
		livenessResp: &LivenessStatus{Confirmed: true},
		matchResp:    &FaceMatchResponse{Matched: true, Similarity: 0.95},
	}
	state := &ServerState{faceVerificationClient: fake}
	rec := httptest.NewRecorder()
	ok := verifyFaceBeforeIssuance(state, rec, "img", "txn-1", "passport")
	require.True(t, ok)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestWriteIssuanceResponse_Success(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	require.NoError(t, storage.StoreToken("sess-1", "nonce"))
	state := &ServerState{tokenStorage: storage, irmaServerURL: "https://irma.example"}
	rec := httptest.NewRecorder()

	ok := writeIssuanceResponse(state, rec, "the-jwt", "sess-1")
	require.True(t, ok)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp IssuanceResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Equal(t, "the-jwt", resp.Jwt)
	require.Equal(t, "https://irma.example", resp.IrmaServerURL)

	// The one-time session token must be consumed.
	_, err := storage.RetrieveToken("sess-1")
	require.Error(t, err)
}
