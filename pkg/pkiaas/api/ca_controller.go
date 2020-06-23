package api

import (
	"encoding/json"
	"net/http"

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
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	authHeader := r.Header.Get("Authorization")
	err := backend.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	err = backend.Backend.GetAccessControl().AdminOnly(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	var intermediateRequest types.IntermediateRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&intermediateRequest)
	if err != nil {
		httpErr := httperror.RequestDecodeFail(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	intermediateResponse, httpErr := pki.GenerateIntermediateCSR(intermediateRequest, backend.Backend)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	err = json.NewEncoder(w).Encode(intermediateResponse)
	if err != nil {
		httpErr := httperror.ResponseEncodeError(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
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
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	authHeader := r.Header.Get("Authorization")
	err := backend.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	err = backend.Backend.GetAccessControl().AdminOnly(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	var signedCert types.PEMCertificate
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&signedCert)
	if err != nil {
		httpErr := httperror.RequestDecodeFail(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}
}

// GetCAHandler ----------------------------------------------------------------------
// Handler to retrieve the base64-encoded DER intermediate CA certificate from the storage backend
// and return it in PEM format
func GetCAHandler(w http.ResponseWriter, r *http.Request) {
	pemCA, httpErr := pki.GetCA(backend.Backend)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}
	_, err := w.Write(pemCA)
	if err != nil {
		httpErr := httperror.ResponseWriteError(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}
}

// GetCAChainHandler -----------------------------------------------------------------
// Handler to retrieve the base64-encoded DER intermediate CA certificates associated with
// the CA chain from the storage backend and return them in PEM format
func GetCAChainHandler(w http.ResponseWriter, r *http.Request) {
	caChainBundle, httpErr := pki.GetCAChain(backend.Backend)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}
	err := json.NewEncoder(w).Encode(caChainBundle)
	if err != nil {
		httpErr := httperror.ResponseEncodeError(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}
}

// SetCAChainHandler -----------------------------------------------------------------
// Handler to capture a PEM encoded certificate bundle from the request and parse it
// into individual DER certificates. Each of these certificates are stored in base64
// format in the storage backend
func SetCAChainHandler(w http.ResponseWriter, r *http.Request) {
	if !pki.ValidateContentType(r.Header, "application/json") {
		httpErr := httperror.InvalidContentType()
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	authHeader := r.Header.Get("Authorization")
	err := backend.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	err = backend.Backend.GetAccessControl().AdminOnly(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	var pemBundle types.PEMCertificateBundle
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&pemBundle)
	if err != nil {
		httpErr := httperror.RequestDecodeFail(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}
	httpErr := pki.SetCAChain(pemBundle, backend.Backend)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}
}

// GetCRLHandler ----------------------------------------------------
// Handler to retrieve the DER encoded CRL from the storage backend
func GetCRLHandler(w http.ResponseWriter, r *http.Request) {
	decodedCRL, httpErr := pki.GetCRL(backend.Backend)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}
	_, err := w.Write(decodedCRL)
	if err != nil {
		httpErr := httperror.ResponseWriteError(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}
}

// PurgeHandler -----------------------------------------------------
// Handler that will purge all expired certificates from both the certificate
// repository in the storage backend, as well as the CRL, within a given buffer
// time that is passed in the request
func PurgeHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	err := backend.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	err = backend.Backend.GetAccessControl().Purge(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}
}

// PurgeCRLHandler --------------------------------------------------
// Handler that will purge all expired certificates from the CRL
// within a given buffer time that is passed in the request
func PurgeCRLHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	err := backend.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}

	err = backend.Backend.GetAccessControl().CRLPurge(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.ErrorCode+": "+httpErr.ErrorMessage, httpErr.HTTPResponse)
		return
	}
}
