package pki

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// CreateTemplateHandler ---------------------------------------------------
// Handler method to capture JSON input from HTTP POST request and parse it
// into a types.Template object. Data from the request is validated and then
// stored in backend
func (p *Pki) CreateTemplateHandler(w http.ResponseWriter, r *http.Request) {
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "CPKICT001: Unable to read request body - "+err.Error(), http.StatusBadRequest)
		return
	}

	if !ValidateContentType(r.Header, "application/json") {
		http.Error(w, "CPKICT002: Invalid HTTP Content-Type header - expected application/json", http.StatusUnsupportedMediaType)
		return
	}

	// Ensure that the requesting entity can both authenticate to the PKI service, as well as
	// has authorization to access the Create Template endpoint
	authHeader := r.Header.Get("Authorization")
	err = p.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		http.Error(w, "CPKICT003: Invalid authentication from header - "+err.Error(), http.StatusUnauthorized)
		return
	}
	err = p.Backend.GetAccessControl().CreateTemplate(authHeader)
	if err != nil {
		http.Error(w, "CPKICT004: Not authorized to create new template - "+err.Error(), http.StatusForbidden)
		return
	}

	var newTemplate types.Template
	err = json.Unmarshal(reqBody, &newTemplate)
	if err != nil {
		http.Error(w, "CPKICT005: Not able to unmarshal request body data - "+err.Error(), http.StatusBadRequest)
		return
	}

	_, err = p.Backend.GetTemplate(newTemplate.TemplateName)
	if err == nil {
		http.Error(w, "CPKICT006: Template "+newTemplate.TemplateName+" already exists", http.StatusBadRequest)
		return
	}
	// Validate and sanitize all input from HTTP request

	err = ValidateKeyAlgoAndSize(newTemplate.KeyAlgo, newTemplate.KeyBits)
	if err != nil {
		http.Error(w, "CPKICT007: Invalid key algorithm or size - "+err.Error(), http.StatusBadRequest)
		return
	}

	// Check for any errors returned from processing key usages and extended key usages
	// to validate they are all presented in proper format
	_, err = ProcessKeyUsages(newTemplate.KeyUsages)
	if err != nil {
		http.Error(w, "CPKICT008: Error validating key usages - "+err.Error(), http.StatusBadRequest)
		return
	}
	_, err = ProcessExtKeyUsages(newTemplate.ExtKeyUsages)
	if err != nil {
		http.Error(w, "CPKICT009: Error validating extended key usages - "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate any policy identifier OIDs that are sent in the request
	_, err = ProcessPolicyIdentifiers(newTemplate.PolicyIdentifiers)
	if err != nil {
		http.Error(w, "CPKICT010: Error validating policy identifiers - "+err.Error(), http.StatusBadRequest)
		return
	}

	// Store the newly created template object in the backend
	err = p.Backend.CreateTemplate(newTemplate)
	if err != nil {
		http.Error(w, "CPKICT011: Unable to store the new template - "+err.Error(), http.StatusBadRequest)
		return
	}
}

// ManageTemplateHandler -------------------------------------------------------
// Handler method to capture JSON input from HTTP POST request and parse it
// into a types.Template object. Retrieves existing template from backend and
// updates its properties with the new request and overwrites the old template.
func (p *Pki) ManageTemplateHandler(w http.ResponseWriter, r *http.Request) {
	reqBody, err := ioutil.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "CPKIMT001: Unable to read request body - "+err.Error(), http.StatusBadRequest)
		return
	}

	if !ValidateContentType(r.Header, "application/json") {
		http.Error(w, "CPKIMT002: Invalid HTTP Content-Type header - expected application/json", http.StatusUnsupportedMediaType)
		return
	}

	// Ensure that the requesting entity can both authenticate to the PKI service. 	Then parse the
	// request body first in order to get template name for authorization check to ensure the requstor
	// has authorization to access the Manage Template endpoint as well as the specific template
	authHeader := r.Header.Get("Authorization")
	err = p.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		http.Error(w, "CPKIMT003: Invalid authentication from header - "+err.Error(), http.StatusUnauthorized)
		return
	}
	var newTemplate types.Template
	err = json.Unmarshal(reqBody, &newTemplate)
	if err != nil {
		http.Error(w, "CPKIMT004: Not able to unmarshal request body data - "+err.Error(), http.StatusBadRequest)
		return
	}
	err = p.Backend.GetAccessControl().ManageTemplate(authHeader, newTemplate.TemplateName)
	if err != nil {
		http.Error(w, "CPKIMT005: Not authorized to manage template "+newTemplate.TemplateName+" - "+err.Error(), http.StatusForbidden)
		return
	}

	template, err := p.Backend.GetTemplate(newTemplate.TemplateName)
	if err != nil {
		http.Error(w, "CPKIMT006: Unable to retrieve template from storage backend - "+err.Error(), http.StatusBadRequest)
		return
	}
	template.Subject = newTemplate.Subject
	err = json.Unmarshal(reqBody, &template)
	if err != nil {
		http.Error(w, "CPKIMT007: Not able to unmarshal stored template data - "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate and sanitize all input from HTTP request
	err = ValidateKeyAlgoAndSize(template.KeyAlgo, template.KeyBits)
	if err != nil {
		http.Error(w, "CPKIMT008: Invalid key algorithm or size - "+err.Error(), http.StatusBadRequest)
		return
	}

	// Check for any errors returned from processing key usages and extended key usages
	// to validate they are all presented in proper format
	_, err = ProcessKeyUsages(template.KeyUsages)
	if err != nil {
		http.Error(w, "CKPIMT009: Error validating key usages - "+err.Error(), http.StatusBadRequest)
		return
	}
	_, err = ProcessExtKeyUsages(template.ExtKeyUsages)
	if err != nil {
		http.Error(w, "CKPIMT010: Error validating extended key usages - "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate permitted/excluded data
	_, err = ProcessPolicyIdentifiers(template.PolicyIdentifiers)
	if err != nil {
		http.Error(w, "CKPIMT011: Error validating policy identifiers - "+err.Error(), http.StatusBadRequest)
		return
	}

	// "Update" the template by deleting the old one and creating a new one with the
	// same name
	err = p.Backend.DeleteTemplate(template.TemplateName)
	if err != nil {
		http.Error(w, "CKPIMT012: Error deleting template from storage backend - "+err.Error(), http.StatusInternalServerError)
		return
	}
	err = p.Backend.CreateTemplate(template)
	if err != nil {
		http.Error(w, "CKPIMT013: Error creating new template in storage backend - "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// DeleteTemplateHandler -------------------------------------------------------
// Handler method to delete a template from the storage backend that is retrieved
// from a URI variable
func (p *Pki) DeleteTemplateHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")

	// Ensure that the requesting entity can both authenticate to the PKI service, then extract
	// the template name from the URI and test that it has authorization to access the
	// Delete Template endpoint for the requested template
	err := p.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		http.Error(w, "CPKIDT001: Invalid authentication from header - "+err.Error(), http.StatusUnauthorized)
		return
	}

	templateName := mux.Vars(r)["templateName"]

	err = p.Backend.GetAccessControl().DeleteTemplate(authHeader, templateName)
	if err != nil {
		http.Error(w, "CPKIDT002: Not authorized to delete template "+templateName+" - "+err.Error(), http.StatusForbidden)
		return
	}
	err = p.Backend.DeleteTemplate(templateName)
	if err != nil {
		http.Error(w, "CPKIDT003: Error deleting template from storage backend - "+err.Error(), http.StatusNotFound)
		return
	}
}

// GetTemplateHandler ----------------------------------------------------------
// Handler method to retrieve a template from the storage backend using a URI
// variable and return its JSON representation
func (p *Pki) GetTemplateHandler(w http.ResponseWriter, r *http.Request) {

	// Ensure that the requesting entity can both authenticate to the PKI service, then extract
	// the template name from the URI and test that it has authorization to access the
	// Get Template endpoint for the requested template
	authHeader := r.Header.Get("Authorization")
	err := p.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		http.Error(w, "CPKIDT001: Invalid authentication from header - "+err.Error(), http.StatusUnauthorized)
		return
	}

	templateName := mux.Vars(r)["templateName"]

	err = p.Backend.GetAccessControl().ReadTemplate(authHeader, templateName)
	if err != nil {
		http.Error(w, "CPKIDT002: Not authorized to read template "+templateName+" - "+err.Error(), http.StatusForbidden)
		return
	}

	template, err := p.Backend.GetTemplate(templateName)

	if err != nil {
		http.Error(w, "CPKIDT003: Error reading template from storage backend - "+err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(template)
	if err != nil {
		http.Error(w, "CPKIDT004: Error encoding template response - "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// ListTemplatesHandler ---------------------------------------------------------
// Handler method to retrieve a list of all templates from the storage backend using
// and return its JSON representation
func (p *Pki) ListTemplatesHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")

	// Ensure that the requesting entity can both authenticate to the PKI service, as well as
	// has authorization to access the List Templates endpoint
	err := p.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		http.Error(w, "CPKILT001: Invalid authentication from header - "+err.Error(), http.StatusUnauthorized)
		return
	}

	err = p.Backend.GetAccessControl().ReadTemplates(authHeader)
	if err != nil {
		http.Error(w, "CPKILT002: Not authorized to list all templates - "+err.Error(), http.StatusForbidden)
		return
	}

	templates, err := p.Backend.ListTemplates()
	if err != nil {
		http.Error(w, "CPKILT003: Failed to retrieve template list from storage backend - "+err.Error(), http.StatusBadRequest)
		return
	}
	respTemplates := types.TemplateListResponse{
		Templates: templates,
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(respTemplates)
	if err != nil {
		http.Error(w, "CPKIDT004: Error encoding template list response - "+err.Error(), http.StatusInternalServerError)
		return
	}
}
