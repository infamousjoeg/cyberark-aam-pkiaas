package api_test

import (
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend/dummy"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/pki"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/pkg/pkiaas/api"
)

// // TEST: SignCertHandler ------------------------------------------------------
type MockFailAuthorizationSignCert struct {
	dummy.Dummy
}

func (m MockFailAuthorizationSignCert) GetAccessControl() backend.Access {
	return MockAccessControlFailAuthorizationSignCert{}
}

type MockAccessControlFailAuthorizationSignCert struct {
	dummy.AccessControl
}

func (m MockAccessControlFailAuthorizationSignCert) SignCertificate(accessToken string, templateName string) error {
	return fmt.Errorf("Authorization Failed")
}

// func TestSignCertHandler(t *testing.T) {
// body := "valid body"
// req := newHttpRequest("POST", "/certificate/sign", body, false)
// context.Set(req, "Storage", dummyBackend())
// rr := httptest.NewRecorder()
// handler := http.HandlerFunc(api.SignCertHandler)
// handler.ServeHTTP(rr, req)
// assertStatusCode(t, rr, 200)
// }

func TestInvalidContentTypeSignCertHandler(t *testing.T) {
	body := "invalid body"
	req := newHttpRequest("POST", "/certificate/sign", body, false)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.SignCertHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 415)
}

func TestInvalidBodySignCertHandler(t *testing.T) {
	body := "invalid body"
	req := newHttpRequest("POST", "/certificate/sign", body, true)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.SignCertHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 400)
}

func TestFailAuthenticationSignCertHandler(t *testing.T) {
	body := "invalid body"
	req := newHttpRequest("POST", "/certificate/sign", body, true)
	context.Set(req, "Storage", MockFailAuthenticate{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.SignCertHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 401)
}

func TestFailAuthorizationSignCertHandler(t *testing.T) {
	body := `
	{
		"csr": "somecsr",
		"commonName": "some.common.name",
		"templateName": "TemplateName",
		"ttl": 1440
	}
	`
	req := newHttpRequest("POST", "/ca/generate", body, true)
	context.Set(req, "Storage", MockFailAuthorizationSignCert{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.SignCertHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 403)
	fmt.Println(rr.Body.String())
}

// TEST: CreateCertHandler ------------------------------------------------------
type MockFailAuthorizationCreateCert struct {
	dummy.Dummy
}

func (m MockFailAuthorizationCreateCert) GetAccessControl() backend.Access {
	return MockAccessControlFailAuthorizationCreateCert{}
}

type MockAccessControlFailAuthorizationCreateCert struct {
	dummy.AccessControl
}

func (m MockAccessControlFailAuthorizationCreateCert) CreateCertificate(accessToken string, templateName string) error {
	return fmt.Errorf("Authorization Failed")
}

func TestCreateCertHandler(t *testing.T) {
	body := `{"templateName": "TestTemplate", "commonName": "testing.local"}`
	req := newHttpRequest("POST", "/certificate/create", body, true)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.CreateCertHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 200)
}

func TestInvalidContentTypeCreateCertHandler(t *testing.T) {
	body := `{"templateName": "TestTemplate", "commonName": "testing.local"}`
	req := newHttpRequest("POST", "/certificate/create", body, false)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.CreateCertHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 415)
}

func TestInvalidBodyCreateCertHandler(t *testing.T) {
	body := `invalid body`
	req := newHttpRequest("POST", "/certificate/create", body, true)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.CreateCertHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 400)
}

func TestFailAuthenticationCreateCertHandler(t *testing.T) {
	body := `invalid body`
	req := newHttpRequest("POST", "/certificate/create", body, true)
	context.Set(req, "Storage", MockFailAuthenticate{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.CreateCertHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 401)
}

func TestFailAuthorizationCreateCertHandler(t *testing.T) {
	body := `{"templateName": "TestTemplate", "commonName": "testing.local"}`
	req := newHttpRequest("POST", "/certificate/create", body, true)
	context.Set(req, "Storage", MockFailAuthorizationCreateCert{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.CreateCertHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 403)
}

// TEST: GetCertHandler ------------------------------------------------------
type MockFailAuthorizationGetCert struct {
	dummy.Dummy
}

func (m MockFailAuthorizationGetCert) GetAccessControl() backend.Access {
	return MockAccessControlFailAuthorizationGetCert{}
}

type MockAccessControlFailAuthorizationGetCert struct {
	dummy.AccessControl
}

func (m MockAccessControlFailAuthorizationGetCert) GetCertificate(accessToken string, serialNumber string) error {
	return fmt.Errorf("Authorization Failed")
}

func TestGetCertHandler(t *testing.T) {
	serial := big.NewInt(10351605685901192)
	octet, _ := pki.ConvertSerialIntToOctetString(serial)
	req := newHttpRequest("GET", "/certificate/10351605685901192", "", false)
	req = mux.SetURLVars(req, map[string]string{"serialNumber": octet})
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.GetCertHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 200)
}

func TestInvalidSerialNumberGetCertHandler(t *testing.T) {
	serial := big.NewInt(1035160568590119)
	octet, _ := pki.ConvertSerialIntToOctetString(serial)
	req := newHttpRequest("GET", "/certificate/1035160568590119", "", false)
	req = mux.SetURLVars(req, map[string]string{"serialNumber": octet})
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.GetCertHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 404)
}

func TestFailAuthenticationGetCertHandler(t *testing.T) {
	serial := big.NewInt(10351605685901192)
	octet, _ := pki.ConvertSerialIntToOctetString(serial)
	req := newHttpRequest("GET", "/certificate/10351605685901192", "", false)
	req = mux.SetURLVars(req, map[string]string{"serialNumber": octet})
	context.Set(req, "Storage", MockFailAuthenticate{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.GetCertHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 401)
}

// TEST: ListCertsHandler ------------------------------------------------------
func TestListCertsHandler(t *testing.T) {
	req := newHttpRequest("GET", "/certificates", "", false)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.ListCertsHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 200)
}

func TestFailAuthenticationListCertsHandler(t *testing.T) {
	req := newHttpRequest("GET", "/certificates", "", false)
	context.Set(req, "Storage", MockFailAuthenticate{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.ListCertsHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 401)
}

// TEST: RevokeCertHandler ------------------------------------------------------
type MockFailAuthorizationRevokeCert struct {
	dummy.Dummy
}

func (m MockFailAuthorizationRevokeCert) GetAccessControl() backend.Access {
	return MockAccessControlFailAuthorizationRevokeCert{}
}

type MockAccessControlFailAuthorizationRevokeCert struct {
	dummy.AccessControl
}

func (m MockAccessControlFailAuthorizationRevokeCert) RevokeCertificate(accessToken string, templateName string) error {
	return fmt.Errorf("Authorization Failed")
}

func TestRevokeCertHandler(t *testing.T) {
	serial := big.NewInt(10351605685901192)
	octet, _ := pki.ConvertSerialIntToOctetString(serial)
	body := fmt.Sprintf(`
	  {
		  "serialNumber": "%s",
		  "reason": "keyCompromise"
	  }
	`, octet)
	req := newHttpRequest("GET", "/certificate/revoke", body, true)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.RevokeCertHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 200)
}

func TestInvalidContentTypeRevokeCertHandler(t *testing.T) {
	serial := big.NewInt(10351605685901192)
	octet, _ := pki.ConvertSerialIntToOctetString(serial)
	body := fmt.Sprintf(`
	  {
		  "serialNumber": "%s",
		  "reason": "keyCompromise"
	  }
	`, octet)
	req := newHttpRequest("GET", "/certificate/revoke", body, false)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.RevokeCertHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 415)
}

func TestInvalidBodyRevokeCertHandler(t *testing.T) {
	body := "invalid body"
	req := newHttpRequest("GET", "/certificate/revoke", body, true)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.RevokeCertHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 400)
}

func TestFailAuthenticationRevokeCertHandler(t *testing.T) {
	body := "invalid body"
	req := newHttpRequest("GET", "/certificate/revoke", body, true)
	context.Set(req, "Storage", MockFailAuthenticate{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.RevokeCertHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 401)
}

func TestFailAuthorizationRevokeCertHandler(t *testing.T) {
	serial := big.NewInt(10351605685901192)
	octet, _ := pki.ConvertSerialIntToOctetString(serial)
	body := fmt.Sprintf(`
	  {
		  "serialNumber": "%s",
		  "reason": "keyCompromise"
	  }
	`, octet)
	req := newHttpRequest("GET", "/certificate/revoke", body, true)
	context.Set(req, "Storage", MockFailAuthorizationRevokeCert{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.RevokeCertHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 403)
}
