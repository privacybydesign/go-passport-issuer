package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go-passport-issuer/models"

	"github.com/stretchr/testify/require"
)

// fakeFaceMatcher is a configurable test double for FaceMatcher.
type fakeFaceMatcher struct {
	resp      *FaceMatchResponse
	err       error
	healthErr error
	gotDoc    []byte
	gotLive   []byte
	calls     int
}

func (f *fakeFaceMatcher) MatchImages(documentImage, liveImage []byte) (*FaceMatchResponse, error) {
	f.calls++
	f.gotDoc = documentImage
	f.gotLive = liveImage
	return f.resp, f.err
}

func (f *fakeFaceMatcher) HealthCheck() error { return f.healthErr }

// regulaEvidence builds variant A evidence for the shared verifyFaceBeforeIssuance tests.
func regulaEvidence(transactionID string) faceEvidence {
	return faceEvidence{LivenessTransactionID: transactionID}
}

// irisEvidence builds variant B evidence around a live face crop.
func irisEvidence(liveFacePng string) faceEvidence {
	return faceEvidence{OnDevice: &models.FaceVerificationEvidence{
		Method:      FaceVerificationMethodIris,
		LiveFacePng: liveFacePng,
	}}
}

// pngBytes renders a solid PNG of the given size.
func pngBytes(t *testing.T, width, height int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{R: 200, G: 150, B: 120, A: 255})
		}
	}
	var buf bytes.Buffer
	require.NoError(t, png.Encode(&buf, img))
	return buf.Bytes()
}

func pngBase64(t *testing.T, width, height int) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(pngBytes(t, width, height))
}

// decodeLiveFacePng --------------------------------------------------------

func TestDecodeLiveFacePng_Valid(t *testing.T) {
	want := pngBytes(t, 128, 160)
	got, err := decodeLiveFacePng(base64.StdEncoding.EncodeToString(want))
	require.NoError(t, err)
	require.Equal(t, want, got, "the decoded bytes must be passed through untouched")
}

func TestDecodeLiveFacePng_Empty(t *testing.T) {
	_, err := decodeLiveFacePng("")
	require.ErrorContains(t, err, "required")
}

func TestDecodeLiveFacePng_NotBase64(t *testing.T) {
	_, err := decodeLiveFacePng("not base64!!")
	require.ErrorContains(t, err, "base64")
}

func TestDecodeLiveFacePng_NotPng(t *testing.T) {
	_, err := decodeLiveFacePng(base64.StdEncoding.EncodeToString([]byte("\xff\xd8\xff\xe0 definitely a jpeg")))
	require.ErrorContains(t, err, "not a PNG")
}

func TestDecodeLiveFacePng_TooSmall(t *testing.T) {
	_, err := decodeLiveFacePng(pngBase64(t, 32, 32))
	require.ErrorContains(t, err, "too small")
}

func TestDecodeLiveFacePng_TooLargeDimensions(t *testing.T) {
	// Only the header is read, so a huge declared size is cheap to test: hand
	// craft a PNG header claiming 5000x5000 on top of a real small image.
	real := pngBytes(t, 64, 64)
	forged := append([]byte{}, real...)
	// IHDR width/height are big-endian at offsets 16 and 20.
	forged[16], forged[17], forged[18], forged[19] = 0, 0, 0x13, 0x88 // 5000
	forged[20], forged[21], forged[22], forged[23] = 0, 0, 0x13, 0x88 // 5000
	_, err := decodeLiveFacePng(base64.StdEncoding.EncodeToString(forged))
	require.Error(t, err)
	// Either the CRC check or the dimension check rejects it; both are fine
	// as long as it is rejected without decoding pixels.
}

func TestDecodeLiveFacePng_TooManyBytes(t *testing.T) {
	// 3 MiB of base64 is rejected on length before any decoding happens.
	oversized := strings.Repeat("A", (maxLiveFaceBytes/3*4)+4096)
	_, err := decodeLiveFacePng(oversized)
	require.ErrorContains(t, err, "exceeds")
}

// performOnDeviceFaceMatch --------------------------------------------------

func TestPerformOnDeviceFaceMatch_MatcherNotConfigured(t *testing.T) {
	result, err := performOnDeviceFaceMatch(&ServerState{}, "ZG9j", irisEvidence(pngBase64(t, 128, 128)).OnDevice)
	require.Error(t, err)
	require.Nil(t, result)
}

func TestPerformOnDeviceFaceMatch_UnsupportedMethod(t *testing.T) {
	fake := &fakeFaceMatcher{resp: &FaceMatchResponse{Matched: true, Similarity: 1}}
	state := &ServerState{faceMatcher: fake}
	evidence := &models.FaceVerificationEvidence{Method: "something-else", LiveFacePng: pngBase64(t, 128, 128)}

	result, err := performOnDeviceFaceMatch(state, "ZG9j", evidence)
	require.ErrorContains(t, err, "unsupported")
	require.Nil(t, result)
	require.Equal(t, 0, fake.calls)
}

func TestPerformOnDeviceFaceMatch_MissingDocumentImage(t *testing.T) {
	fake := &fakeFaceMatcher{resp: &FaceMatchResponse{Matched: true, Similarity: 1}}
	state := &ServerState{faceMatcher: fake}

	result, err := performOnDeviceFaceMatch(state, "", irisEvidence(pngBase64(t, 128, 128)).OnDevice)
	require.ErrorContains(t, err, "document photo")
	require.Nil(t, result)
	require.Equal(t, 0, fake.calls)
}

func TestPerformOnDeviceFaceMatch_InvalidLiveFace(t *testing.T) {
	fake := &fakeFaceMatcher{resp: &FaceMatchResponse{Matched: true, Similarity: 1}}
	state := &ServerState{faceMatcher: fake}

	result, err := performOnDeviceFaceMatch(state, "ZG9j", irisEvidence("@@not-base64@@").OnDevice)
	require.Error(t, err)
	require.Nil(t, result)
	require.Equal(t, 0, fake.calls, "an invalid crop must be rejected before the matcher is called")
}

func TestPerformOnDeviceFaceMatch_MatcherError(t *testing.T) {
	fake := &fakeFaceMatcher{err: errors.New("sidecar down")}
	state := &ServerState{faceMatcher: fake}

	result, err := performOnDeviceFaceMatch(state, "ZG9j", irisEvidence(pngBase64(t, 128, 128)).OnDevice)
	require.ErrorContains(t, err, "sidecar down")
	require.Nil(t, result)
}

func TestPerformOnDeviceFaceMatch_Success(t *testing.T) {
	fake := &fakeFaceMatcher{resp: &FaceMatchResponse{Matched: true, Similarity: 0.62}}
	state := &ServerState{faceMatcher: fake}
	live := pngBytes(t, 128, 128)
	document := []byte("raw-dg2-jpeg")
	evidence := &models.FaceVerificationEvidence{
		Method:        FaceVerificationMethodIris,
		LiveFacePng:   base64.StdEncoding.EncodeToString(live),
		ClientOutcome: "matched",
	}

	result, err := performOnDeviceFaceMatch(state, base64.StdEncoding.EncodeToString(document), evidence)
	require.NoError(t, err)
	require.True(t, result.Matched)
	require.Equal(t, 0.62, result.Similarity)
	require.Equal(t, FaceVerificationMethodIris, result.Method)

	// The matcher receives the raw chip image and the raw PNG crop, decoded
	// from their base64 transport encoding.
	require.Equal(t, document, fake.gotDoc)
	require.Equal(t, live, fake.gotLive)
}

// verifyFaceBeforeIssuance, variant B paths ----------------------------------

// A Regula-only issuer that receives on-device evidence must refuse it rather
// than fall back to trusting the client's verdict.
func TestVerifyFaceBeforeIssuance_OnDevice_NoMatcherConfigured(t *testing.T) {
	state := &ServerState{faceVerificationClient: &fakeFaceClient{}}
	rec := httptest.NewRecorder()

	ok := verifyFaceBeforeIssuance(state, rec, "ZG9j", irisEvidence(pngBase64(t, 128, 128)), "passport")
	require.False(t, ok)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "not supported")
}

func TestVerifyFaceBeforeIssuance_MixedEvidenceRejected(t *testing.T) {
	regula := &fakeFaceClient{livenessResp: &LivenessStatus{Confirmed: true}, matchResp: &FaceMatchResponse{Matched: true, Similarity: 1}}
	matcher := &fakeFaceMatcher{resp: &FaceMatchResponse{Matched: true, Similarity: 1}}
	state := &ServerState{faceVerificationClient: regula, faceMatcher: matcher}
	rec := httptest.NewRecorder()

	evidence := irisEvidence(pngBase64(t, 128, 128))
	evidence.LivenessTransactionID = "txn-1"
	ok := verifyFaceBeforeIssuance(state, rec, "ZG9j", evidence, "passport")
	require.False(t, ok)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "not both")
	require.Equal(t, 0, matcher.calls)
	require.False(t, regula.deleteCalled, "no Regula call may be made for mixed evidence")
}

func TestVerifyFaceBeforeIssuance_OnDevice_NotMatched(t *testing.T) {
	state := &ServerState{faceMatcher: &fakeFaceMatcher{resp: &FaceMatchResponse{Matched: false, Similarity: 0.12}}}
	rec := httptest.NewRecorder()

	ok := verifyFaceBeforeIssuance(state, rec, "ZG9j", irisEvidence(pngBase64(t, 128, 128)), "passport")
	require.False(t, ok)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "face verification failed")
}

func TestVerifyFaceBeforeIssuance_OnDevice_MatcherError(t *testing.T) {
	state := &ServerState{faceMatcher: &fakeFaceMatcher{err: errors.New("boom")}}
	rec := httptest.NewRecorder()

	ok := verifyFaceBeforeIssuance(state, rec, "ZG9j", irisEvidence(pngBase64(t, 128, 128)), "passport")
	require.False(t, ok)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestVerifyFaceBeforeIssuance_OnDevice_MissingCrop(t *testing.T) {
	matcher := &fakeFaceMatcher{resp: &FaceMatchResponse{Matched: true, Similarity: 1}}
	state := &ServerState{faceMatcher: matcher}
	rec := httptest.NewRecorder()

	ok := verifyFaceBeforeIssuance(state, rec, "ZG9j", irisEvidence(""), "passport")
	require.False(t, ok)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Equal(t, 0, matcher.calls)
}

// Variant B works with no Regula client at all.
func TestVerifyFaceBeforeIssuance_OnDevice_PassesWithoutRegula(t *testing.T) {
	state := &ServerState{faceMatcher: &fakeFaceMatcher{resp: &FaceMatchResponse{Matched: true, Similarity: 0.8}}}
	rec := httptest.NewRecorder()

	ok := verifyFaceBeforeIssuance(state, rec, "ZG9j", irisEvidence(pngBase64(t, 128, 128)), "passport")
	require.True(t, ok)
	require.Equal(t, http.StatusOK, rec.Code)
}

// A matcher-only issuer that receives a Regula transaction id cannot verify
// it and must reject, not skip.
func TestVerifyFaceBeforeIssuance_RegulaEvidenceWithoutRegula(t *testing.T) {
	state := &ServerState{faceMatcher: &fakeFaceMatcher{resp: &FaceMatchResponse{Matched: true, Similarity: 1}}}
	rec := httptest.NewRecorder()

	ok := verifyFaceBeforeIssuance(state, rec, "ZG9j", regulaEvidence("txn-1"), "passport")
	require.False(t, ok)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "not supported")
}

// Fail-closed also holds for a matcher-only issuer: no evidence, no credential.
func TestVerifyFaceBeforeIssuance_MatcherOnly_MissingEvidence(t *testing.T) {
	state := &ServerState{faceMatcher: &fakeFaceMatcher{}}
	rec := httptest.NewRecorder()

	ok := verifyFaceBeforeIssuance(state, rec, "ZG9j", faceEvidence{}, "passport")
	require.False(t, ok)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "face verification required")
}

// Enabled flag, methods and config --------------------------------------------

func TestFaceVerificationEnabled_FollowsMatcherPresence(t *testing.T) {
	require.True(t, (&ServerState{faceMatcher: &fakeFaceMatcher{}}).faceVerificationEnabled())
}

func TestFaceVerificationMethods(t *testing.T) {
	require.Equal(t, []string{}, (&ServerState{}).faceVerificationMethods())
	require.Equal(t, []string{"regula"}, (&ServerState{faceVerificationClient: &fakeFaceClient{}}).faceVerificationMethods())
	require.Equal(t, []string{"iris"}, (&ServerState{faceMatcher: &fakeFaceMatcher{}}).faceVerificationMethods())
	require.Equal(t, []string{"regula", "iris"},
		(&ServerState{faceVerificationClient: &fakeFaceClient{}, faceMatcher: &fakeFaceMatcher{}}).faceVerificationMethods())
}

func TestResolveFaceVerification_MatcherOnly(t *testing.T) {
	enabled, err := resolveFaceVerificationEnabled(&Config{
		FaceMatcherUrl:       "http://face-matcher:8000",
		FaceMatcherThreshold: 0.4,
	})
	require.NoError(t, err)
	require.True(t, enabled, "a configured matcher enables face verification without any Regula setting")
}

func TestResolveFaceVerification_MatcherRequiresThreshold(t *testing.T) {
	_, err := resolveFaceVerificationEnabled(&Config{FaceMatcherUrl: "http://face-matcher:8000"})
	require.ErrorContains(t, err, "face_matcher_threshold")

	_, err = resolveFaceVerificationEnabled(&Config{FaceMatcherUrl: "http://face-matcher:8000", FaceMatcherThreshold: -1})
	require.ErrorContains(t, err, "face_matcher_threshold")
}

func TestResolveFaceVerification_EnabledWithoutAnyMethod(t *testing.T) {
	_, err := resolveFaceVerificationEnabled(&Config{FaceVerificationEnabled: boolPtr(true)})
	require.ErrorContains(t, err, "face_matcher_url")
}

func TestResolveFaceVerification_BothMethods(t *testing.T) {
	enabled, err := resolveFaceVerificationEnabled(&Config{
		RegulaFaceApiUrl:       "http://regula-face-api:41101",
		RegulaFaceApiPublicUrl: "https://faceapi.example",
		FaceMatcherUrl:         "http://face-matcher:8000",
		FaceMatcherThreshold:   0.4,
	})
	require.NoError(t, err)
	require.True(t, enabled)
}

// Announcement ---------------------------------------------------------------

func TestStartValidationAnnouncesIrisOnly(t *testing.T) {
	state := &ServerState{
		tokenStorage: NewInMemoryTokenStorage(),
		faceMatcher:  &fakeFaceMatcher{},
	}

	rec := httptest.NewRecorder()
	handleStartValidatePassport(state, rec, httptest.NewRequest(http.MethodPost, "/api/start-validation", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	// No Regula, so no Face API URL for the app to run liveness against.
	require.NotContains(t, rec.Body.String(), "face_api_url")

	var response ValidatePassportResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	require.NotNil(t, response.FaceVerification)
	require.Equal(t, []string{"iris"}, response.FaceVerification.Methods)
}

func TestStartValidationAnnouncesBothMethods(t *testing.T) {
	state := &ServerState{
		tokenStorage:           NewInMemoryTokenStorage(),
		faceVerificationClient: &fakeFaceClient{},
		faceMatcher:            &fakeFaceMatcher{},
		regulaFaceApiPublicUrl: "https://faceapi.staging.yivi.app",
	}

	response := startValidationWith(t, state)
	require.NotNil(t, response.FaceVerification)
	require.Equal(t, "https://faceapi.staging.yivi.app", response.FaceVerification.FaceApiUrl)
	require.Equal(t, []string{"regula", "iris"}, response.FaceVerification.Methods)
}

// Request decoding -----------------------------------------------------------

func TestValidationRequestDecodesOnDeviceEvidence(t *testing.T) {
	body := `{"session_id":"s","nonce":"n","data_groups":{},"ef_sod":"",
	  "face_verification":{"method":"iris","live_face_png":"AAAA","client_outcome":"matched"}}`
	var request models.ValidationRequest
	require.NoError(t, json.Unmarshal([]byte(body), &request))
	require.NotNil(t, request.FaceVerification)
	require.Equal(t, "iris", request.FaceVerification.Method)
	require.Equal(t, "AAAA", request.FaceVerification.LiveFacePng)
	require.Equal(t, "matched", request.FaceVerification.ClientOutcome)

	evidence := faceEvidenceFrom(&request)
	require.NotNil(t, evidence.OnDevice)
	require.False(t, evidence.mixed())
}
