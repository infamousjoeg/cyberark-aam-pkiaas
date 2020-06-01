package pki

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"reflect"

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

	oldTemplate, err := GetTemplateFromDAP(newTemplate.TemplateName)
	if err != nil {
		http.Error(w, "The requested template "+newTemplate.TemplateName+" cannot be located", http.StatusBadRequest)
		return
	}
	rNewTemplate := reflect.ValueOf(newTemplate)
	rOldTemplate := reflect.ValueOf(&oldTemplate)
	rOldTemplate = rOldTemplate.Elem()
	typeTemplate := rNewTemplate.Type()
	for i := 0; i < rNewTemplate.NumField(); i++ {
		if rNewTemplate.Field(i).Interface() != "" {
			fieldName := typeTemplate.Field(i).Name
			newField := rOldTemplate.FieldByName(fieldName)
			newValue := rNewTemplate.Field(i).Interface().(string)
			newField.SetString(newValue)
		}
	}
	err = DeleteTemplateFromDAP(newTemplate.TemplateName)

}

// DeleteTemplateHandler -------------------------------------------------------
func DeleteTemplateHandler(w http.ResponseWriter, r *http.Request) {
	templateName := mux.Vars(r)["templateName"]
	err := DeleteTemplateFromDAP(templateName)
	if err != nil {
		http.Error(w, "Unable to delete requested template", http.StatusInternalServerError)
		return
	}
}

// GetTemplateHandler ----------------------------------------------------------
func GetTemplateHandler(w http.ResponseWriter, r *http.Request) {
	template, err := GetTemplateFromDAP(mux.Vars(r)["templateName"])

	if err != nil {
		http.Error(w, "Unable to retrieve requested template", http.StatusBadRequest)
		return
	}
	respTemplate, err := json.Marshal(template)

	if err != nil {
		http.Error(w, "The requested template was unable to be successfully processed into a response: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(respTemplate)
}

// ListTemplatesHandler ---------------------------------------------------------
func ListTemplatesHandler(w http.ResponseWriter, r *http.Request) {
	templates, err := GetAllTemplatesFromDAP()

	if err != nil {
		http.Error(w, "Failed to retrieve a list of templates", http.StatusBadRequest)
		return
	}
	templateObject := types.TemplateListResponse{
		Templates: templates,
	}
	respTemplates, err := json.Marshal(templateObject)
	if err != nil {
		http.Error(w, "The server was unable to process the template list into an appropriate response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(respTemplates)
}
