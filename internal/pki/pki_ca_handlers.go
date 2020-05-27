package pki

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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
	if err != nil {
		http.Error(w, "Unable to process request body data.  JSON Unmarshal returned error: "+err.Error(), http.StatusBadRequest)
		return
	}

	signPrivKey, _, err := GenerateKeys(intermediateRequest.KeyAlgo, intermediateRequest.KeyBits)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	certSubject, err := SetCertSubject(intermediateRequest.Subject, intermediateRequest.CommonName)
	dnsNames, emailAddresses, ipAddresses, URIs, err := ProcessSubjectAltNames(intermediateRequest.AltNames)
	if err != nil {
		http.Error(w, "Error handling request Subject Alternate Names: "+err.Error(), http.StatusBadRequest)
		return
	}
	signRequest := x509.CertificateRequest{
		Subject:        certSubject,
		DNSNames:       dnsNames,
		EmailAddresses: emailAddresses,
		IPAddresses:    ipAddresses,
		URIs:           URIs,
	}
	signCSR, err := x509.CreateCertificateRequest(rand.Reader, &signRequest, signPrivKey)
	if err != nil {
		http.Error(w, "Unable to generate new certificate request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	pemSignCSR := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: signCSR})

	csrResponse := types.PEMCSR{CSR: string(pemSignCSR)}

	json.NewEncoder(w).Encode(csrResponse)
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
	pemCert, rest := pem.Decode([]byte(signedCert.Certificate))
	if len(rest) > 0 {
		http.Error(w, "The signed certificate is not in a valid PEM format", http.StatusBadRequest)
		return
	}
	derCert := pemCert.Bytes
	WriteSigningCertToDAP(base64.StdEncoding.EncodeToString(derCert))
}

// GetCAHandler ----------------------------------------------------------------------
func GetCAHandler(w http.ResponseWriter, r *http.Request) {
	encodedCA, err := GetSigningCertFromDAP()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	decodedCA, err := base64.StdEncoding.DecodeString(encodedCA)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	pemCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: decodedCA})
	w.Write(pemCA)
}

// GetCAChainHandler -----------------------------------------------------------------
func GetCAChainHandler(w http.ResponseWriter, r *http.Request) {
	caChain := ""
	encodedBundle, err := GetCAChainFromDAP()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	for _, encodedCert := range encodedBundle {
		derCert, err := base64.StdEncoding.DecodeString(encodedCert)
		if err != nil {
			http.Error(w, "Error processing CA chain: "+err.Error(), http.StatusInternalServerError)
		}
		pemCert := pem.Block{Type: "CERTIFICATE", Bytes: derCert}
		caChain += string(pem.EncodeToMemory(&pemCert))
	}
	caChainBundle := types.PEMCertificateBundle{
		CertBundle: caChain,
	}

	json.NewEncoder(w).Encode(caChainBundle)
}

// SetCAChainHandler -----------------------------------------------------------------
func SetCAChainHandler(w http.ResponseWriter, r *http.Request) {
	reqBody, err := ioutil.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}

	if !ValidateContentType(r.Header, "application/json") {
		http.Error(w, "Invalid content type: expected application/json", http.StatusUnsupportedMediaType)
		return
	}

	var pemBundle types.PEMCertificateBundle
	err = json.Unmarshal(reqBody, &pemBundle)
	if err != nil {
		http.Error(w, "Unable to process request body data.  JSON Unmarshal returned error: "+err.Error(), http.StatusBadRequest)
		return
	}
	var certBundle []string
	for pemCert, remainder := pem.Decode([]byte(pemBundle.CertBundle)); len(remainder) > 0; {
		derCert := pemCert.Bytes
		encodedCert := base64.StdEncoding.EncodeToString(derCert)
		certBundle = append(certBundle, encodedCert)
	}
	err = WriteCAChainToDAP(certBundle)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
