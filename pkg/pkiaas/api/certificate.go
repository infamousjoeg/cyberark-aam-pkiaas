package api

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

// GetCertificate route //
// Returns signed certificate based on serial number given
func GetCertificate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serialNumber := vars["serialNumber"]
	fmt.Fprintf(w, "Successful GET /certificate/%s", serialNumber)
}

// ListCertificates route //
// Returns all certificates signed by the CA
func ListCertificates(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Successful GET /certificates")
}
