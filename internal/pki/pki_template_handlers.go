package pki

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// CreateTemplateHandler ---------------------------------------------------
func CreateTemplateHandler(w http.ResponseWriter, r *http.Request) {
	reqBody, err := ioutil.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "Unable to read request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if !ValidateContentType(r.Header, "application/json") {
		http.Error(w, "Invalid content type: expected application/json", http.StatusUnsupportedMediaType)
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

	CreateTemplateInDAP(newTemplate)
}

// ManageTemplateHandler -------------------------------------------------------
func ManageTemplateHandler(w http.ResponseWriter, r *http.Request) {
	reqBody, err := ioutil.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "Unable to read request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if !ValidateContentType(r.Header, "application/json") {
		http.Error(w, "Invalid content type: expected application/json", http.StatusUnsupportedMediaType)
		return
	}

	var newTemplate types.Template
	err = json.Unmarshal(reqBody, &newTemplate)
	if err != nil {
		http.Error(w, "Unable to process request body data.  JSON Unmarshal returned error: "+err.Error(), http.StatusBadRequest)
		return
	}

	template, err := GetTemplateFromDAP(newTemplate.TemplateName)
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

	err = DeleteTemplateFromDAP(template.TemplateName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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

	err = CreateTemplateInDAP(template)
}

// DeleteTemplateHandler -------------------------------------------------------
func DeleteTemplateHandler(w http.ResponseWriter, r *http.Request) {
	templateName := mux.Vars(r)["templateName"]
	err := DeleteTemplateFromDAP(templateName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
}

// GetTemplateHandler ----------------------------------------------------------
func GetTemplateHandler(w http.ResponseWriter, r *http.Request) {
	template, err := GetTemplateFromDAP(mux.Vars(r)["templateName"])

	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(template)
}

// ListTemplatesHandler ---------------------------------------------------------
func ListTemplatesHandler(w http.ResponseWriter, r *http.Request) {
	templates, err := GetAllTemplatesFromDAP()

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
