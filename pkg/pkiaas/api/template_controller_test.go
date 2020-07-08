package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gorilla/context"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend/dummy"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/httperror"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/pkg/pkiaas/api"
)

func dummyBackend() dummy.Dummy {
	return dummy.Dummy{}
}

func assertNoHttpError(t *testing.T, err httperror.HTTPError) {
	empty := httperror.HTTPError{}
	if err != empty {
		t.Errorf("Unexpected error occured. %v", err)
	}
}

func TestListTemplatesHandlerSuccess(t *testing.T) {
	req, err := http.NewRequest("GET", "/templates", nil)
	if err != nil {
		t.Fatal(err)
	}

	context.Set(req, "Storage", dummyBackend())

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.ListTemplatesHandler)
	handler.ServeHTTP(rr, req)

	if rr.Result().StatusCode != 200 {
		t.Errorf("Did not receive expected HTTP response code of 200")
	}

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

func TestListTemplatesHandlerFail(t *testing.T) {
	req, err := http.NewRequest("GET", "/templates", nil)
	if err != nil {
		t.Fatal(err)
	}

	context.Set(req, "Storage", dummyBackend())

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(api.ListTemplatesHandler)
	handler.ServeHTTP(rr, req)

	if rr.Result().StatusCode != 200 {
		t.Errorf("Did not receive expected HTTP response code of 200")
	}

	expected := types.TemplateListResponse{Templates: []string{"Template3", "Template4"}}
	var result types.TemplateListResponse
	err = json.Unmarshal(rr.Body.Bytes(), &result)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(expected, result) {
		t.Errorf("The received result incorrectly matched an unexpected response value")
	}
}
