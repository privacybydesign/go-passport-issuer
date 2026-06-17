package main

import (
	"context"
	"encoding/json"
	"go-passport-issuer/document/edl"
	"go-passport-issuer/models"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gmrtd/gmrtd/document"
	"github.com/stretchr/testify/require"
)

// fakeFaceSessionCreator records the portrait it received and returns a canned
// session (or error).
type fakeFaceSessionCreator struct {
	gotPortrait string
	called      bool
	session     *FaceSession
	err         error
}

func (f *fakeFaceSessionCreator) CreateSession(_ context.Context, portrait string) (*FaceSession, error) {
	f.called = true
	f.gotPortrait = portrait
	return f.session, f.err
}

// photoConverter is a fake DocumentDataConverter returning a fixed DG2 portrait.
type photoConverter struct{ photo string }

func (c photoConverter) ToPassportData(_ document.Document, _ bool) (models.PassportData, error) {
	return models.PassportData{DocumentNumber: "X", Photo: c.photo}, nil
}
func (photoConverter) ToDrivingLicenceData(_ edl.DrivingLicenceDocument, _ bool) (models.EDLData, error) {
	return models.EDLData{DocumentNumber: "123"}, nil
}

func TestNewFaceVerificationClientDisabledWhenNoURL(t *testing.T) {
	require.Nil(t, NewFaceVerificationClient(FaceVerificationConfig{}))
	require.Nil(t, NewFaceVerificationClient(FaceVerificationConfig{URL: "   "}))
	require.NotNil(t, NewFaceVerificationClient(FaceVerificationConfig{URL: "https://face.example"}))
}

func TestFaceClientCreateSessionSuccess(t *testing.T) {
	var gotBody faceSessionRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/face/session", r.URL.Path)
		b, _ := io.ReadAll(r.Body)
		require.NoError(t, json.Unmarshal(b, &gotBody))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(faceSessionResponse{
			FaceSessionID:    "fs_abc123",
			FaceSessionToken: "tok",
			BindingSecret:    "secret-should-not-leak",
			WebsocketURL:     "wss://face.example/stream/fs_abc123",
			BindingKeyReady:  true,
		})
	}))
	defer srv.Close()

	client := NewFaceVerificationClient(FaceVerificationConfig{
		URL:         srv.URL,
		VerifierID:  "passport-issuer",
		CallbackURL: "https://issuer.example/cb",
	})
	require.NotNil(t, client)

	session, err := client.CreateSession(context.Background(), "base64-dg2-portrait")
	require.NoError(t, err)
	require.Equal(t, "fs_abc123", session.FaceSessionID)
	require.Equal(t, "tok", session.FaceSessionToken)
	require.Equal(t, "wss://face.example/stream/fs_abc123", session.WebsocketURL)
	require.True(t, session.BindingKeyReady)

	// Request carried the DG2 portrait and config values.
	require.Equal(t, "base64-dg2-portrait", gotBody.PortraitImage)
	require.Equal(t, "passport-issuer", gotBody.VerifierID)
	require.Equal(t, "https://issuer.example/cb", gotBody.CallbackURL)
}

func TestFaceClientCreateSessionErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	client := NewFaceVerificationClient(FaceVerificationConfig{URL: srv.URL})
	_, err := client.CreateSession(context.Background(), "portrait")
	require.Error(t, err)
	require.Contains(t, err.Error(), "500")
}

func TestFaceClientCreateSessionEmptyPortrait(t *testing.T) {
	client := NewFaceVerificationClient(FaceVerificationConfig{URL: "https://face.example"})
	_, err := client.CreateSession(context.Background(), "")
	require.Error(t, err)
}

// Integration: verify-passport returns a face_session when the creator is set
// and a DG2 portrait is available.
func TestVerifyPassportReturnsFaceSession(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	creator := &fakeFaceSessionCreator{session: &FaceSession{
		FaceSessionID:    "fs_xyz",
		FaceSessionToken: "tok",
		WebsocketURL:     "wss://face.example/stream/fs_xyz",
		BindingKeyReady:  true,
	}}
	startTestServer(t, storage, func(s *ServerState) {
		s.faceSessionCreator = creator
		s.converter = photoConverter{photo: "dg2-portrait-base64"}
	})

	session, nonce := startValidation(t)
	req := newReq(session, nonce)

	resp, body, decoded := postJSON[VerificationResponse](t, "http://localhost:8081/api/verify-passport", req)
	mustStatus(t, resp, http.StatusOK, body)

	require.True(t, creator.called)
	require.Equal(t, "dg2-portrait-base64", creator.gotPortrait)
	require.NotNil(t, decoded.FaceSession)
	require.Equal(t, "fs_xyz", decoded.FaceSession.FaceSessionID)
	// Binding secret must never appear in the response body.
	require.NotContains(t, string(body), "binding_secret")
}

// Backwards compatibility: with no creator configured the response has no
// face_session field at all.
func TestVerifyPassportNoFaceSessionWhenDisabled(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	startTestServer(t, storage)

	session, nonce := startValidation(t)
	req := newReq(session, nonce)

	resp, body, decoded := postJSON[VerificationResponse](t, "http://localhost:8081/api/verify-passport", req)
	mustStatus(t, resp, http.StatusOK, body)
	require.Nil(t, decoded.FaceSession)
	require.NotContains(t, string(body), "face_session")
}

// Non-fatal: a face service failure must not fail passport validation.
func TestVerifyPassportFaceSessionFailureIsNonFatal(t *testing.T) {
	storage := NewInMemoryTokenStorage()
	creator := &fakeFaceSessionCreator{err: io.ErrUnexpectedEOF}
	startTestServer(t, storage, func(s *ServerState) {
		s.faceSessionCreator = creator
		s.converter = photoConverter{photo: "dg2-portrait-base64"}
	})

	session, nonce := startValidation(t)
	req := newReq(session, nonce)

	resp, body, decoded := postJSON[VerificationResponse](t, "http://localhost:8081/api/verify-passport", req)
	mustStatus(t, resp, http.StatusOK, body)
	require.True(t, creator.called)
	require.Nil(t, decoded.FaceSession)
}
