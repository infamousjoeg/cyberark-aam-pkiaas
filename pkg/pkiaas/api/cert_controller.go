package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/httperror"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/pki"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// SignCertHandler -------------------------------------------------------------
// Handler method to read a CSR from HTTP request and generate a CA-signed certificate
// from it. Before being signed, the CSR's properties and extensions are compared
// against a template
func SignCertHandler(w http.ResponseWriter, r *http.Request) {
	if !pki.ValidateContentType(r.Header, "application/json") {
		httpErr := httperror.InvalidContentType()
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	// Ensure that the requesting entity can both authenticate to the PKI service, as well as
	// has authorization to access the Sign Certificate endpoint using the requested template
	authHeader := r.Header.Get("Authorization")
	err := backend.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	var signReq types.SignRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&signReq)
	if err != nil {
		httpErr := httperror.RequestDecodeFail(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	err = backend.Backend.GetAccessControl().SignCertificate(authHeader, signReq.TemplateName)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	response, httpErr := pki.SignCert(signReq, backend.Backend)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		httpErr := httperror.ResponseWriteError(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
}

// CreateCertHandler -----------------------------------------------------------
// Handler method used to build a new certificate with the provided common name
// based upon the provided template
func CreateCertHandler(w http.ResponseWriter, r *http.Request) {
	if !pki.ValidateContentType(r.Header, "application/json") {
		httpErr := httperror.InvalidContentType()
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	// Ensure that the requesting entity can both authenticate to the PKI service, as well as
	// has authorization to access the Create Certificate endpoint using the requested template
	authHeader := r.Header.Get("Authorization")
	err := backend.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	var certReq types.CreateCertReq
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&certReq)
	if err != nil {
		httpErr := httperror.RequestDecodeFail(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	err = backend.Backend.GetAccessControl().CreateCertificate(authHeader, certReq.TemplateName)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	response, httpErr := pki.CreateCert(certReq, backend.Backend)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		httpErr := httperror.ResponseWriteError(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
}

// GetCertHandler --------------------------------------------------------------------
func GetCertHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	serialNumber := mux.Vars(r)["serialNumber"]

	// Ensure that the requesting entity can both authenticate to the PKI service, but there
	// is no need for an authorization check as all authenticated entities will be allowed
	// to retrieve public certificate data
	err := backend.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	response, httpErr := pki.GetCert(serialNumber, backend.Backend)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		httpErr := httperror.ResponseEncodeError(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
}

// ListCertsHandler ------------------------------------------------------------------
// Handler method used to retrieve the serial number of all certificates currently
// in the backend storage repository and return them
func ListCertsHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")

	// Ensure that the requesting entity can both authenticate to the PKI service, but there
	// is no need for an authorization check as all authenticated entities will be allowed
	// to retrieve public certificate data
	err := backend.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	response, httpErr := pki.ListCerts(backend.Backend)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		httpErr := httperror.ResponseEncodeError(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
}

// RevokeCertHandler -----------------------------------------------------------------
// Handler method that updates to revoke a certificate for a specified, but optional,
// reason code.  Updates the certificate object in the storage backend as well as generates
// a new CRL
func RevokeCertHandler(w http.ResponseWriter, r *http.Request) {
	if !pki.ValidateContentType(r.Header, "application/json") {
		httpErr := httperror.InvalidContentType()
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	// Ensure that the requesting entity can both authenticate to the PKI service, as well as
	// has authorization to access the Revoke Certificate endpoint for the specified serial number
	authHeader := r.Header.Get("Authorization")
	err := backend.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	var crlReq = types.RevokeRequest{}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&crlReq)
	if err != nil {
		httpErr := httperror.RequestDecodeFail(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	err = backend.Backend.GetAccessControl().RevokeCertificate(authHeader, crlReq.SerialNumber)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	httpErr := pki.RevokeCert(crlReq, backend.Backend)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
}
