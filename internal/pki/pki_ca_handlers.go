package pki

import (
	"crypto/rand"
	"crypto/x509"
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

	signPrivKey, _, err := GenerateKeys(intermediateRequest.KeyAlgo, intermediateRequest.KeyBits)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	signRequest := x509.CertificateRequest{}
	signCSR, err := x509.CreateCertificateRequest(rand.Reader, &signRequest, signPrivKey)
	if err != nil {
		http.Error("")
	}
}

// SetIntermediateCertHandler ----------------------------------------------
func SetIntermediateCertHandler(w http.ResponseWriter, r *http.Request) {
	reqBody, err := ioutil.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "Unable to read request body: "+err.Error(), http.StatusBadRequest)
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
