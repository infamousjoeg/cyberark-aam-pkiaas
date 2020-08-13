package api

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/httperror"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/pki"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// CreateTemplateHandler ---------------------------------------------------
// Handler method to capture JSON input from HTTP POST request and parse it
// into a types.Template object. Data from the request is validated and then
// stored in backend
func CreateTemplateHandler(w http.ResponseWriter, r *http.Request) {
	if !pki.ValidateContentType(r.Header, "application/json") {
		httpErr := httperror.InvalidContentType()
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	// Ensure that the requesting entity can both authenticate to the PKI service, as well as
	// has authorization to access the Create Template endpoint
	storage := context.Get(r, "Storage").(backend.Storage)
	authHeader := r.Header.Get("Authorization")
	err := storage.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	err = storage.GetAccessControl().CreateTemplate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	newTemplate := &types.Template{StoreCertificate: true}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&newTemplate)
	if err != nil {
		httpErr := httperror.RequestDecodeFail(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	httpErr := pki.CreateTemplate(*newTemplate, storage)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
}

// GetTemplateHandler ----------------------------------------------------------
// Handler method to retrieve a template from the storage backend using a URI
// variable and return its JSON representation
func GetTemplateHandler(w http.ResponseWriter, r *http.Request) {

	// Ensure that the requesting entity can both authenticate to the PKI service, then extract
	// the template name from the URI and test that it has authorization to access the
	// Get Template endpoint for the requested template
	storage := context.Get(r, "Storage").(backend.Storage)
	authHeader := r.Header.Get("Authorization")
	err := storage.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	templateName := mux.Vars(r)["templateName"]

	err = storage.GetAccessControl().ReadTemplate(authHeader, templateName)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	template, httpErr := pki.GetTemplate(templateName, storage)

	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(template)
	if err != nil {
		httpErr := httperror.ResponseEncodeError(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
}

// ManageTemplateHandler -------------------------------------------------------
// Handler method to capture JSON input from HTTP POST request and parse it
// into a types.Template object. Retrieves existing template from backend and
// updates its properties with the new request and overwrites the old template.
func ManageTemplateHandler(w http.ResponseWriter, r *http.Request) {
	if !pki.ValidateContentType(r.Header, "application/json") {
		httpErr := httperror.InvalidContentType()
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		httpErr := httperror.RequestDecodeFail(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	// Ensure that the requesting entity can both authenticate to the PKI service. 	Then parse the
	// request body first in order to get template name for authorization check to ensure the requstor
	// has authorization to access the Manage Template endpoint as well as the specific template
	storage := context.Get(r, "Storage").(backend.Storage)
	authHeader := r.Header.Get("Authorization")
	err = storage.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	var newTemplate types.Template
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&newTemplate)
	if err != nil {
		httpErr := httperror.RequestDecodeFail(err.Error())
		http.Error(w, httpErr.JSON()+"   "+string(body), httpErr.HTTPResponse)
		return
	}
	err = storage.GetAccessControl().ManageTemplate(authHeader, newTemplate.TemplateName)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	template, httpErr := pki.GetTemplate(newTemplate.TemplateName, storage)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	template.Subject = newTemplate.Subject
	decoder = json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&template)
	if err != nil {
		httpErr := httperror.RequestDecodeFail(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	httpErr = pki.DeleteTemplate(template.TemplateName, storage)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	httpErr = pki.CreateTemplate(template, storage)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
}

// DeleteTemplateHandler -------------------------------------------------------
// Handler method to delete a template from the storage backend that is retrieved
// from a URI variable
func DeleteTemplateHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")

	// Ensure that the requesting entity can both authenticate to the PKI service, then extract
	// the template name from the URI and test that it has authorization to access the
	// Delete Template endpoint for the requested template
	storage := context.Get(r, "Storage").(backend.Storage)
	err := storage.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	templateName := mux.Vars(r)["templateName"]

	err = storage.GetAccessControl().DeleteTemplate(authHeader, templateName)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	httpErr := pki.DeleteTemplate(templateName, storage)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListTemplatesHandler ---------------------------------------------------------
// Handler method to retrieve a list of all templates from the storage backend using
// and return its JSON representation
func ListTemplatesHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")

	// Ensure that the requesting entity can both authenticate to the PKI service, as well as
	// has authorization to access the List Templates endpoint
	storage := context.Get(r, "Storage").(backend.Storage)
	err := storage.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	err = storage.GetAccessControl().ListTemplates(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	templateList, httpErr := pki.ListTemplate(storage)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(templateList)
	if err != nil {
		httpErr := httperror.ResponseEncodeError(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
}
