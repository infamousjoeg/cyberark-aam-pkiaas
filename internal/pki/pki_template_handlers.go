package pki

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// CreateTemplateHandler ---------------------------------------------------
func (p *Pki) CreateTemplateHandler(w http.ResponseWriter, r *http.Request) {
	reqBody, err := ioutil.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "Unable to read request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if !ValidateContentType(r.Header, "application/json") {
		http.Error(w, "Invalid content type: expected application/json", http.StatusUnsupportedMediaType)
		return
	}

	authHeader := r.Header.Get("Authorization")
	err = p.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		http.Error(w, "Invalid authentication: "+err.Error(), http.StatusUnauthorized)
		return
	}

	var newTemplate types.Template
	err = json.Unmarshal(reqBody, &newTemplate)
	if err != nil {
		http.Error(w, "Unable to process request body data.  JSON Unmarshal returned error: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Check for mandatory fields

	err = ValidateKeyAlgoAndSize(newTemplate.KeyAlgo, newTemplate.KeyBits)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Validate and sanitize Subject data

	_, err = ProcessKeyUsages(newTemplate.KeyUsages)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, err = ProcessExtKeyUsages(newTemplate.ExtKeyUsages)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate permitted/excluded data
	_, err = ProcessPolicyIdentifiers(newTemplate.PolicyIdentifiers)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = p.Backend.CreateTemplate(newTemplate)
}

// ManageTemplateHandler -------------------------------------------------------
func (p *Pki) ManageTemplateHandler(w http.ResponseWriter, r *http.Request) {
	reqBody, err := ioutil.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "Unable to read request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if !ValidateContentType(r.Header, "application/json") {
		http.Error(w, "Invalid content type: expected application/json", http.StatusUnsupportedMediaType)
		return
	}

	authHeader := r.Header.Get("Authorization")
	err = p.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		http.Error(w, "Invalid authentication: "+err.Error(), http.StatusUnauthorized)
		return
	}

	var newTemplate types.Template
	err = json.Unmarshal(reqBody, &newTemplate)
	if err != nil {
		http.Error(w, "Unable to process request body data.  JSON Unmarshal returned error: "+err.Error(), http.StatusBadRequest)
		return
	}

	template, err := p.Backend.GetTemplate(newTemplate.TemplateName)
	if err != nil {
		http.Error(w, "The requested template "+newTemplate.TemplateName+" cannot be located", http.StatusBadRequest)
		return
	}
	template.Subject = newTemplate.Subject
	err = json.Unmarshal(reqBody, &template)
	if err != nil {
		http.Error(w, "Unable to process request body data.  JSON Unmarshal returned error: "+err.Error(), http.StatusBadRequest)
		return
	}

	err = ValidateKeyAlgoAndSize(template.KeyAlgo, template.KeyBits)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Validate and sanitize Subject data

	_, err = ProcessKeyUsages(template.KeyUsages)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, err = ProcessExtKeyUsages(template.ExtKeyUsages)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate permitted/excluded data
	_, err = ProcessPolicyIdentifiers(template.PolicyIdentifiers)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = p.Backend.DeleteTemplate(template.TemplateName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	err = p.Backend.CreateTemplate(template)
}

// DeleteTemplateHandler -------------------------------------------------------
func (p *Pki) DeleteTemplateHandler(w http.ResponseWriter, r *http.Request) {
	templateName := mux.Vars(r)["templateName"]
	err := p.Backend.DeleteTemplate(templateName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
}

// GetTemplateHandler ----------------------------------------------------------
func (p *Pki) GetTemplateHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	err := p.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		http.Error(w, "Invalid authentication: "+err.Error(), http.StatusUnauthorized)
		return
	}

	template, err := p.Backend.GetTemplate(mux.Vars(r)["templateName"])

	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(template)
}

// ListTemplatesHandler ---------------------------------------------------------
func (p *Pki) ListTemplatesHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	err := p.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		http.Error(w, "Invalid authentication: "+err.Error(), http.StatusUnauthorized)
		return
	}

	templates, err := p.Backend.ListTemplates()

	if err != nil {
		http.Error(w, "Failed to retrieve a list of templates", http.StatusBadRequest)
		return
	}
	respTemplates := types.TemplateListResponse{
		Templates: templates,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(respTemplates)
}
