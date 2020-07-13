package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend/dummy"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/pkg/pkiaas/api"
)

func dummyBackend() dummy.Dummy {
	return dummy.Dummy{}
}

func assertStatusCode(t *testing.T, rr *httptest.ResponseRecorder, expectedStatusCode int) {
	actualStatusCode := rr.Result().StatusCode
	if actualStatusCode != expectedStatusCode {
		t.Errorf("Recieved status code '%v' and was expected status code '%v'", actualStatusCode, expectedStatusCode)
	}
}

func setContentTypeHeader(r *http.Request) *http.Request {
	r.Header.Set("Content-Type", "application/json")
	return r
}

func newHttpRequest(method string, endpoint string, body string, applicationJson bool) *http.Request {
	rawBody := strings.NewReader(body)
	req, err := http.NewRequest(method, endpoint, rawBody)
	if err != nil {
		panic(err)
	}

	if applicationJson {
		req = setContentTypeHeader(req)
	}

	return req
}

// Fail authenticate
type MockFailAuthenticate struct {
	dummy.Dummy
}

func (m MockFailAuthenticate) GetAccessControl() backend.Access {
	return MockAccessControlFailAuthenticate{}
}

type MockAccessControlFailAuthenticate struct {
	dummy.AccessControl
}

func (m MockAccessControlFailAuthenticate) Authenticate(accessToken string) error {
	return fmt.Errorf("Failed to authenticate to the Mock service")
}

// TEST: CreateTemplateHandler ----------------------------------------------------------------
func createTemplateBody() string {
	body := `
	{
		"templateName": "TestTemplate",
		"keyAlgo": "RSA",
		"keyBits": "2048"
	}
	`
	return body
}

type MockFailAuthorizationCreateTemplate struct {
	dummy.Dummy
}

func (m MockFailAuthorizationCreateTemplate) GetAccessControl() backend.Access {
	return MockAccessControlFailAuthorizationCreateTemplate{}
}

type MockAccessControlFailAuthorizationCreateTemplate struct {
	dummy.AccessControl
}

func (m MockAccessControlFailAuthorizationCreateTemplate) CreateTemplate(accessToken string) error {
	return fmt.Errorf("Authorization Failed")
}

func TestCreateTemplateHandler(t *testing.T) {
	body := createTemplateBody()
	req := newHttpRequest("POST", "/template/create", body, true)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.CreateTemplateHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 200)
}

func TestInvalidBodyCreateTemplateHandler(t *testing.T) {
	body := "invalid body"
	req := newHttpRequest("POST", "/template/create", body, true)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.CreateTemplateHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 400)
}

func TestInvalidContentTypeCreateTemplateHandler(t *testing.T) {
	body := "invalid body"
	req := newHttpRequest("POST", "/template/create", body, false)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.CreateTemplateHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 415)
}

func TestAuthenticateFailCreateTemplateHandler(t *testing.T) {
	body := createTemplateBody()
	req := newHttpRequest("POST", "/template/create", body, true)
	context.Set(req, "Storage", MockFailAuthenticate{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.CreateTemplateHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 401)
}

func TestAuthorizationFailCreateTemplateHandler(t *testing.T) {
	body := createTemplateBody()
	req := newHttpRequest("POST", "/template/create", body, true)
	context.Set(req, "Storage", MockFailAuthorizationCreateTemplate{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.CreateTemplateHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 403)
}

// TEST: GetTemplateHandler ----------------------------------------------------------------
type MockFailAuthorizationGetTemplate struct {
	dummy.Dummy
}

func (m MockFailAuthorizationGetTemplate) GetAccessControl() backend.Access {
	return MockAccessControlFailAuthorizationGetTemplate{}
}

type MockAccessControlFailAuthorizationGetTemplate struct {
	dummy.AccessControl
}

func (m MockAccessControlFailAuthorizationGetTemplate) ReadTemplate(accessToken string, templateName string) error {
	return fmt.Errorf("Authorization Fail")
}

func TestGetTemplateHandler(t *testing.T) {
	req := newHttpRequest("GET", "/template/TestTemplate", "", false)
	req = mux.SetURLVars(req, map[string]string{"templateName": "TestTemplate"})
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.GetTemplateHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 200)
}

func TestNotFoundGetTemplateHandler(t *testing.T) {
	req := newHttpRequest("GET", "/template/notReal", "", false)
	req = mux.SetURLVars(req, map[string]string{"templateName": "notReal"})
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.GetTemplateHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 404)
}

func TestAuthenticationFailGetTemplateHandler(t *testing.T) {
	req := newHttpRequest("GET", "/template/TestTemplate", "", false)
	req = mux.SetURLVars(req, map[string]string{"templateName": "TestTemplate"})
	context.Set(req, "Storage", MockFailAuthenticate{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.GetTemplateHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 401)
}

func TestAuthorizationFailGetTemplateHandler(t *testing.T) {
	req := newHttpRequest("GET", "/template/TestTemplate", "", false)
	req = mux.SetURLVars(req, map[string]string{"templateName": "TestTemplate"})
	context.Set(req, "Storage", MockFailAuthorizationGetTemplate{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.GetTemplateHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 403)
}

// TEST: ManageTemplateHandler ----------------------------------------------------------------
type MockFailAuthorizationManageTemplate struct {
	dummy.Dummy
}

func (m MockFailAuthorizationManageTemplate) GetAccessControl() backend.Access {
	return MockAccessControlFailAuthorizationManageTemplate{}
}

type MockAccessControlFailAuthorizationManageTemplate struct {
	dummy.AccessControl
}

func (m MockAccessControlFailAuthorizationManageTemplate) ManageTemplate(accessToken string, templateName string) error {
	return fmt.Errorf("Authorization Fail")
}

// TODO: This has not been accomplished because this endpoint is throwing the following error
// {"errorCode":"CPKIMT003","errorMessage":"Failed to decode request JSON data - EOF","statusCode":400}
func TestManageTemplateHandler(t *testing.T) {
	body := createTemplateBody()
	req := newHttpRequest("PUT", "/template/manage", body, true)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.ManageTemplateHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 200)
}

func TestInvalidContentTypeManageTemplateHandler(t *testing.T) {
	body := createTemplateBody()
	req := newHttpRequest("PUT", "/template/manage", body, false)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.ManageTemplateHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 415)
}

func TestInvalidBodyManageTemplateHandler(t *testing.T) {
	body := "invalid body"
	req := newHttpRequest("PUT", "/template/manage", body, true)
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.ManageTemplateHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 400)
}

func TestFailAuthenticationManageTemplateHandler(t *testing.T) {
	body := "invalid body"
	req := newHttpRequest("PUT", "/template/manage", body, true)
	context.Set(req, "Storage", MockFailAuthenticate{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.ManageTemplateHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 401)
}

func TestFailAuthorizationManageTemplateHandler(t *testing.T) {
	body := createTemplateBody()
	req := newHttpRequest("PUT", "/template/manage", body, true)
	context.Set(req, "Storage", MockFailAuthorizationManageTemplate{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.ManageTemplateHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 403)
}

// TEST: DeleteTemplateHandler ----------------------------------------------------------------

type MockFailAuthorizationDeleteTemplate struct {
	dummy.Dummy
}

func (m MockFailAuthorizationDeleteTemplate) GetAccessControl() backend.Access {
	return MockAccessControlFailAuthorizationDeleteTemplate{}
}

type MockAccessControlFailAuthorizationDeleteTemplate struct {
	dummy.AccessControl
}

func (m MockAccessControlFailAuthorizationDeleteTemplate) DeleteTemplate(accessToken string, templateName string) error {
	return fmt.Errorf("No Authorization")
}

func TestDeleteTemplateHandler(t *testing.T) {
	req := newHttpRequest("DELETE", "/template/TestTemplate", "", false)
	req = mux.SetURLVars(req, map[string]string{"templateName": "TestTemplate"})
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.DeleteTemplateHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 204)
	fmt.Println(string(rr.Body.Bytes()))
}

func TestDeleteNonExistentTemplateHandler(t *testing.T) {
	req := newHttpRequest("DELETE", "/template/notReal", "", false)
	req = mux.SetURLVars(req, map[string]string{"templateName": "notReal"})
	context.Set(req, "Storage", dummyBackend())
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.DeleteTemplateHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 404)
	fmt.Println(string(rr.Body.Bytes()))
}

func TestAuthenticationFailDeleteTemplateHandler(t *testing.T) {
	req := newHttpRequest("DELETE", "/template/TestTemplate", "", false)
	req = mux.SetURLVars(req, map[string]string{"templateName": "TestTemplate"})
	context.Set(req, "Storage", MockFailAuthenticate{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.DeleteTemplateHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 401)
	fmt.Println(string(rr.Body.Bytes()))
}

func TestAuthorizationFailDeleteTemplateHandler(t *testing.T) {
	req := newHttpRequest("DELETE", "/template/TestTemplate", "", false)
	req = mux.SetURLVars(req, map[string]string{"templateName": "TestTemplate"})
	context.Set(req, "Storage", MockFailAuthorizationDeleteTemplate{})
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.DeleteTemplateHandler)
	handler.ServeHTTP(rr, req)
	assertStatusCode(t, rr, 403)
	fmt.Println(string(rr.Body.Bytes()))
}

// TEST: ListTemplateHandler ----------------------------------------------------------------
// Fail authorization for List Template
type MockFailAuthorizationListTemplates struct {
	dummy.Dummy
}

func (m MockFailAuthorizationListTemplates) GetAccessControl() backend.Access {
	return MockAccessControlFailAuthorizationListTemplates{}
}

type MockAccessControlFailAuthorizationListTemplates struct {
	dummy.AccessControl
}

func (m MockAccessControlFailAuthorizationListTemplates) ListTemplates(accessToken string) error {
	return fmt.Errorf("You do not have authorization to list templates")
}

func TestListTemplatesHandler(t *testing.T) {
	req, err := http.NewRequest("GET", "/templates", nil)
	if err != nil {
		t.Fatal(err)
	}

	context.Set(req, "Storage", dummyBackend())

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.ListTemplatesHandler)
	handler.ServeHTTP(rr, req)

	assertStatusCode(t, rr, 200)

	expected := types.TemplateListResponse{Templates: []string{"Template1", "Template2"}}
	var result types.TemplateListResponse
	err = json.Unmarshal(rr.Body.Bytes(), &result)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expected, result) {
		t.Errorf("The received result did not match the expected template list response")
	}
}

func TestAuthenticateFailListTemplatesHandler(t *testing.T) {
	req, err := http.NewRequest("GET", "/templates", nil)
	if err != nil {
		t.Fatal(err)
	}

	context.Set(req, "Storage", MockFailAuthenticate{})

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.ListTemplatesHandler)
	handler.ServeHTTP(rr, req)

	assertStatusCode(t, rr, 401)
}

func TestAuthorizationFailListTemplatesHandler(t *testing.T) {
	req, err := http.NewRequest("GET", "/templates", nil)
	if err != nil {
		t.Fatal(err)
	}

	context.Set(req, "Storage", MockFailAuthorizationListTemplates{})

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.ListTemplatesHandler)
	handler.ServeHTTP(rr, req)

	assertStatusCode(t, rr, 403)
}
