package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
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
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)

	}

	// Ensure that the requesting entity can both authenticate to the PKI service, as well as
	// has authorization to access the Create Template endpoint
	authHeader := r.Header.Get("Authorization")
	err := backend.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
	}
	err = backend.Backend.GetAccessControl().CreateTemplate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
	}
	var newTemplate types.Template
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&newTemplate)
	if err != nil {
		httpErr := httperror.RequestDecodeFail(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
	}
	httpErr := pki.CreateTemplate(newTemplate, backend.Backend)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
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
	authHeader := r.Header.Get("Authorization")
	err := backend.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	templateName := mux.Vars(r)["templateName"]

	err = backend.Backend.GetAccessControl().ReadTemplate(authHeader, templateName)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	template, httpErr := pki.GetTemplate(templateName, backend.Backend)

	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(template)
	if err != nil {
		httpErr := httperror.ResponseEncodeError(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
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
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	// Ensure that the requesting entity can both authenticate to the PKI service. 	Then parse the
	// request body first in order to get template name for authorization check to ensure the requstor
	// has authorization to access the Manage Template endpoint as well as the specific template
	authHeader := r.Header.Get("Authorization")
	err := backend.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}
	var newTemplate types.Template
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&newTemplate)
	if err != nil {
		httpErr := httperror.RequestDecodeFail(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}
	err = backend.Backend.GetAccessControl().ManageTemplate(authHeader, newTemplate.TemplateName)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	template, httpErr := pki.GetTemplate(newTemplate.TemplateName, backend.Backend)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	template.Subject = newTemplate.Subject
	decoder = json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&template)
	if err != nil {
		httpErr := httperror.RequestDecodeFail(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	httpErr = pki.DeleteTemplate(template.TemplateName, backend.Backend)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	httpErr = pki.CreateTemplate(template, backend.Backend)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
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
	err := backend.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	templateName := mux.Vars(r)["templateName"]

	err = backend.Backend.GetAccessControl().DeleteTemplate(authHeader, templateName)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	httpErr := pki.DeleteTemplate(templateName, backend.Backend)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}
}

// ListTemplatesHandler ---------------------------------------------------------
// Handler method to retrieve a list of all templates from the storage backend using
// and return its JSON representation
func ListTemplatesHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")

	// Ensure that the requesting entity can both authenticate to the PKI service, as well as
	// has authorization to access the List Templates endpoint
	err := backend.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	err = backend.Backend.GetAccessControl().ListTemplates(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	templateList, httpErr := pki.ListTemplate(backend.Backend)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(templateList)
	if err != nil {
		httpErr := httperror.ResponseEncodeError(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}
}
