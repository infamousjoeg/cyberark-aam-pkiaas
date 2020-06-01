package api

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

// GetTemplate route //
// Returns a template from Conjur service based on template name
func GetTemplate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	templateName := vars["templateName"]
	fmt.Fprintf(w, "Successful GET /template/%s", templateName)
}

// ListTemplates route //
// Returns a list of templates created in the Conjur service
func ListTemplates(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Successful GET /templates")
}
