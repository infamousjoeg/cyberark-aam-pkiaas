package api_test

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/context"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend/dummy"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/pkg/pkiaas/api"
)

func assertBodyContains(t *testing.T, rr *httptest.ResponseRecorder, contains string) {
	body := rr.Body.String()
	if !strings.Contains(body, contains) {
		t.Errorf("Body '%s' was expected to contain '%s' but does not", body, contains)
	}
}

// TEST: GenerateIntermediateHandler ---------------------------------------------
func generateIntermediateBody() string {
	return `
	{
		"commonName": "cybr-pkiaas.herokuapp.com",
		"keyAlgo": "RSA",
		"keyBits": "2048"
	}
	`
}

type MockFailAuthorizationGenerateIntermediate struct {
	dummy.Dummy
}

func (m MockFailAuthorizationGenerateIntermediate) GetAccessControl() backend.Access {
	return MockAccessControlFailAuthorizationGenerateIntermediate{}
}

type MockAccessControlFailAuthorizationGenerateIntermediate struct {
	dummy.AccessControl
}

func (m MockAccessControlFailAuthorizationGenerateIntermediate) GenerateIntermediateCSR(accessToken string) error {
	return fmt.Errorf("Authorization Failed")
}

func TestGenerateIntermediateHandler(t *testing.T) {
	body := generateIntermediateBody()
	req := newHttpRequest("POST", "/ca/generate", body, true)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.GenerateIntermediateHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 200)
}

func TestInvalidContentTypeGenerateIntermediateHandler(t *testing.T) {
	body := generateIntermediateBody()
	req := newHttpRequest("POST", "/ca/generate", body, false)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.GenerateIntermediateHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 415)
}

func TestInvalidBodyGenerateIntermediateHandler(t *testing.T) {
	body := "invalid Body"
	req := newHttpRequest("POST", "/ca/generate", body, true)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.GenerateIntermediateHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 400)
}

func TestFailAuthenticationGenerateIntermediateHandler(t *testing.T) {
	body := generateIntermediateBody()
	req := newHttpRequest("POST", "/ca/generate", body, true)
	context.Set(req, "Storage", MockFailAuthenticate{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.GenerateIntermediateHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 401)
}

func TestFailAuthorizationGenerateIntermediateHandler(t *testing.T) {
	body := generateIntermediateBody()
	req := newHttpRequest("POST", "/ca/generate", body, true)
	context.Set(req, "Storage", MockFailAuthorizationGenerateIntermediate{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.GenerateIntermediateHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 403)
}

// TEST: SetIntermediateCertHandler ---------------------------------------------
type MockFailAuthorizationSetIntermediateCert struct {
	dummy.Dummy
}

func (m MockFailAuthorizationSetIntermediateCert) GetAccessControl() backend.Access {
	return MockAccessControlFailAuthorizationSetIntermediateCert{}
}

type MockAccessControlFailAuthorizationSetIntermediateCert struct {
	dummy.AccessControl
}

func (m MockAccessControlFailAuthorizationSetIntermediateCert) SetIntermediateCertificate(accessToken string) error {
	return fmt.Errorf("Authorization Failed")
}

func TestSetIntermediateCertHandler(t *testing.T) {
	backend := dummyBackend()
	encodedCert, _ := backend.GetSigningCert()
	derCert, _ := base64.StdEncoding.DecodeString(encodedCert)
	pem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
	pemObj := types.PEMCertificate{
		Certificate: string(pem),
	}
	body, _ := json.Marshal(pemObj)
	req := newHttpRequest("POST", "/ca/generate", string(body), true)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.SetIntermediateCertHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 200)
}

func TestInvalidPemFormatSetIntermediateCertHandler(t *testing.T) {
	body := `{"certificate": "someCertificate"}`
	req := newHttpRequest("POST", "/ca/generate", body, true)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.SetIntermediateCertHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 400)
	assertBodyContains(t, rr, "Certificate from request is not in valid PEM format")
}

func TestInvalidBodySetIntermediateCertHandler(t *testing.T) {
	body := `invalid body`
	req := newHttpRequest("POST", "/ca/generate", body, true)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.SetIntermediateCertHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 400)
	assertBodyContains(t, rr, "Failed to decode request JSON data")
}

func TestInvalidContentTypeSetIntermediateCertHandler(t *testing.T) {
	body := `{"certificate": "someCertificate"}`
	req := newHttpRequest("POST", "/ca/generate", body, false)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.SetIntermediateCertHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 415)
}

func TestFailAuthenticationSetIntermediateCertHandler(t *testing.T) {
	body := `{"certificate": "someCertificate"}`
	req := newHttpRequest("POST", "/ca/generate", string(body), true)
	context.Set(req, "Storage", MockFailAuthenticate{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.SetIntermediateCertHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 401)
}

func TestFailAuthorizationSetIntermediateCertHandler(t *testing.T) {
	body := `{"certificate": "someCertificate"}`
	req := newHttpRequest("POST", "/ca/generate", string(body), true)
	context.Set(req, "Storage", MockFailAuthorizationSetIntermediateCert{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.SetIntermediateCertHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 403)
}

// TEST: GetCAHandler ---------------------------------------------
func TestGetCAHandler(t *testing.T) {
	req := newHttpRequest("GET", "/ca/certificate", "", false)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.GetCAHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 200)
}

// TEST: GetCAHandler ---------------------------------------------
func TestGetCAChainHandler(t *testing.T) {
	req := newHttpRequest("GET", "/ca/chain", "", false)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.GetCAChainHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 200)
}

// TEST: SetCAChainHandler ---------------------------------------------
type MockFailAuthorizationSetCAChain struct {
	dummy.Dummy
}

func (m MockFailAuthorizationSetCAChain) GetAccessControl() backend.Access {
	return MockAccessControlFailAuthorizationSetCAChain{}
}

type MockAccessControlFailAuthorizationSetCAChain struct {
	dummy.AccessControl
}

func (m MockAccessControlFailAuthorizationSetCAChain) SetCAChain(accessToken string) error {
	return fmt.Errorf("Authorization Failed")
}

// func TestSetCAChainHandler(t *testing.T) {
// 	body := "I do not know the valid body"
// 	req := newHttpRequest("POST", "/ca/chain/set", body, true)
// 	context.Set(req, "Storage", dummyBackend())
// 	rr := httptest.NewRecorder()
// 	handler := http.HandlerFunc(api.SetCAChainHandler)
// 	handler.ServeHTTP(rr, req)
// 	assertStatusCode(t, rr, 200)
// }

func TestInvalidBodySetCAChainHandler(t *testing.T) {
	body := "not valid"
	req := newHttpRequest("POST", "/ca/chain/set", body, true)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.SetCAChainHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 400)
}

func TestFailAuthenticationSetCAChainHandler(t *testing.T) {
	body := "not valid"
	req := newHttpRequest("POST", "/ca/chain/set", body, true)
	context.Set(req, "Storage", MockFailAuthenticate{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.SetCAChainHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 401)
}

func TestFailAuthorizationSetCAChainHandler(t *testing.T) {
	body := "not valid"
	req := newHttpRequest("POST", "/ca/chain/set", body, true)
	context.Set(req, "Storage", MockFailAuthorizationSetCAChain{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.SetCAChainHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 403)
}

// TEST: GetCRLHandler ---------------------------------------------
func TestGetCRLHandler(t *testing.T) {
	req := newHttpRequest("GET", "/crl", "", false)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.GetCRLHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 200)
}

// TEST: PurgeHandler ---------------------------------------------
type MockFailAuthorizationPurge struct {
	dummy.Dummy
}

func (m MockFailAuthorizationPurge) GetAccessControl() backend.Access {
	return MockAccessControlFailAuthorizationPurge{}
}

type MockAccessControlFailAuthorizationPurge struct {
	dummy.AccessControl
}

func (m MockAccessControlFailAuthorizationPurge) Purge(accessToken string) error {
	return fmt.Errorf("Authorization Failed")
}

func TestPurgeHandler(t *testing.T) {
	req := newHttpRequest("POST", "/purge", "", false)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.PurgeHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 200)
}

func TestFailAuthenticationPurgeHandler(t *testing.T) {
	req := newHttpRequest("POST", "/purge", "", false)
	context.Set(req, "Storage", MockFailAuthenticate{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.PurgeHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 401)
}

func TestFailAuthorizationPurgeHandler(t *testing.T) {
	req := newHttpRequest("POST", "/purge", "", false)
	context.Set(req, "Storage", MockFailAuthorizationPurge{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.PurgeHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 403)
}

// TEST: PurgeCRLHandler ---------------------------------------------
type MockFailAuthorizationCRLPurge struct {
	dummy.Dummy
}

func (m MockFailAuthorizationCRLPurge) GetAccessControl() backend.Access {
	return MockAccessControlFailAuthorizationCRLPurge{}
}

type MockAccessControlFailAuthorizationCRLPurge struct {
	dummy.AccessControl
}

func (m MockAccessControlFailAuthorizationCRLPurge) CRLPurge(accessToken string) error {
	return fmt.Errorf("Authorization Failed")
}

func TestPurgeCRLHandler(t *testing.T) {
	req := newHttpRequest("POST", "/crl/purge", "", false)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.PurgeCRLHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 200)
}

func TestFailAuthenticationPurgeCRLHandler(t *testing.T) {
	req := newHttpRequest("POST", "/crl/purge", "", false)
	context.Set(req, "Storage", MockFailAuthenticate{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.PurgeCRLHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 401)
}

func TestFailAuthorizationPurgeCRLHandler(t *testing.T) {
	req := newHttpRequest("POST", "/crl/purge", "", false)
	context.Set(req, "Storage", MockFailAuthorizationCRLPurge{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.PurgeCRLHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 403)
}
