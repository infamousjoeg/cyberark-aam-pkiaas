package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/httperror"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/pki"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// GenerateIntermediateCSRHandler ------------------------------------------
// Handler that receives parameters for generating a new intermediate CA and creates
// a CSR to be signed by the enterprise root CA (or another intermediate CA in the chain)
// and creates a new signing key that is stored in backened storage to be used for all
// new certificate generation. Alternatively, if the 'selfSigned' property is passed in
// the request as true, it will generate and return a self-signed CA certificate
func GenerateIntermediateCSRHandler(w http.ResponseWriter, r *http.Request) {
	if !pki.ValidateContentType(r.Header, "application/json") {
		httpErr := httperror.InvalidContentType()
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	authHeader := r.Header.Get("Authorization")
	err := storage.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	err = storage.GetAccessControl().GenerateIntermediateCSR(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	var intermediateRequest types.IntermediateRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&intermediateRequest)
	if err != nil {
		httpErr := httperror.RequestDecodeFail(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	var intermediateResponse types.PEMIntermediate
	var httpErr httperror.HTTPError
	if strings.Contains(strings.ToUpper(r.URL.String()), "SELFSIGNED") {
		intermediateResponse, httpErr = pki.GenerateIntermediate(intermediateRequest, true, storage)
	} else {
		intermediateResponse, httpErr = pki.GenerateIntermediate(intermediateRequest, false, storage)
	}
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	err = json.NewEncoder(w).Encode(intermediateResponse)
	if err != nil {
		httpErr := httperror.ResponseEncodeError(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
}

// SetIntermediateCertHandler ----------------------------------------------
// Handler that accepts the new intermediate CA certificate after it has been signed
// by the enterprise root CA (or another intermediate CA in the chain) and sets it
// as the "signing certificate" for the PKI service
func SetIntermediateCertHandler(w http.ResponseWriter, r *http.Request) {
	if !pki.ValidateContentType(r.Header, "application/json") {
		httpErr := httperror.InvalidContentType()
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	authHeader := r.Header.Get("Authorization")
	err := storage.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	err = storage.GetAccessControl().SetIntermediateCertificate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	var signedCert types.PEMCertificate
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&signedCert)
	if err != nil {
		httpErr := httperror.RequestDecodeFail(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
}

// GetCAHandler ----------------------------------------------------------------------
// Handler to retrieve the base64-encoded DER intermediate CA certificate from the storage storage
// and return it in PEM format
func GetCAHandler(w http.ResponseWriter, r *http.Request) {
	pemCA, httpErr := pki.GetCA(storage)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	_, err := w.Write(pemCA)
	if err != nil {
		httpErr := httperror.ResponseWriteError(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
}

// GetCAChainHandler -----------------------------------------------------------------
// Handler to retrieve the base64-encoded DER intermediate CA certificates associated with
// the CA chain from the storage storage and return them in PEM format
func GetCAChainHandler(w http.ResponseWriter, r *http.Request) {
	caChainBundle, httpErr := pki.GetCAChain(storage)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	err := json.NewEncoder(w).Encode(caChainBundle)
	if err != nil {
		httpErr := httperror.ResponseEncodeError(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
}

// SetCAChainHandler -----------------------------------------------------------------
// Handler to capture a PEM encoded certificate bundle from the request and parse it
// into individual DER certificates. Each of these certificates are stored in base64
// format in the storage storage
func SetCAChainHandler(w http.ResponseWriter, r *http.Request) {
	if !pki.ValidateContentType(r.Header, "application/json") {
		httpErr := httperror.InvalidContentType()
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	authHeader := r.Header.Get("Authorization")
	err := storage.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	err = storage.GetAccessControl().SetCAChain(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	var pemBundle types.PEMCertificateBundle
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&pemBundle)
	if err != nil {
		httpErr := httperror.RequestDecodeFail(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	httpErr := pki.SetCAChain(pemBundle, storage)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
}

// GetCRLHandler ----------------------------------------------------
// Handler to retrieve the DER encoded CRL from the storage storage
func GetCRLHandler(w http.ResponseWriter, r *http.Request) {
	decodedCRL, httpErr := pki.GetCRL(storage)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	_, err := w.Write(decodedCRL)
	if err != nil {
		httpErr := httperror.ResponseWriteError(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
}

// PurgeHandler -----------------------------------------------------
// Handler that will purge all expired certificates from both the certificate
// repository in the storage storage, as well as the CRL, within a given buffer
// time that is passed in the request
func PurgeHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	err := storage.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	err = storage.GetAccessControl().Purge(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
}

// PurgeCRLHandler --------------------------------------------------
// Handler that will purge all expired certificates from the CRL
// within a given buffer time that is passed in the request
func PurgeCRLHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	err := storage.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	err = storage.GetAccessControl().CRLPurge(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
}
