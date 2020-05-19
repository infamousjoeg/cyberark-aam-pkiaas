package pki

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// GenerateIntermediateCSRHandler ------------------------------------------
func GenerateIntermediateCSRHandler(w http.ResponseWriter, r *http.Request) {
	reqBody, err := ioutil.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}

	if !ValidateContentType(r.Header, "application/json") {
		http.Error(w, "Invalid content type: expected application/json", http.StatusUnsupportedMediaType)
		return
	}

	var intermediateRequest types.IntermediateRequest
	err = json.Unmarshal(reqBody, &intermediateRequest)
}

// SetIntermediateCertHandler ----------------------------------------------
func SetIntermediateCertHandler(w http.ResponseWriter, r *http.Request) {
	reqBody, err := ioutil.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}

	if !ValidateContentType(r.Header, "application/json") {
		http.Error(w, "Invalid content type: expected application/json", http.StatusUnsupportedMediaType)
		return
	}
	var signedCert types.PEMCertificate
	err = json.Unmarshal(reqBody, &signedCert)
}

// GetCAHandler ----------------------------------------------------------------------
func GetCAHandler(w http.ResponseWriter, r *http.Request) {

}

// GetCAChainHandler -----------------------------------------------------------------
func GetCAChainHandler(w http.ResponseWriter, r *http.Request) {

}
