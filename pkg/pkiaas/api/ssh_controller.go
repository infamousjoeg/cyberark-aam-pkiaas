package api

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/httperror"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/pki"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/ssh"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// CreateSSHTemplateHandler Accepts the HTTP request with all the required information to create a new
// SSH tempalte and passes it to the SSH service
func CreateSSHTemplateHandler(w http.ResponseWriter, r *http.Request) {
	if !pki.ValidateContentType(r.Header, "application/json") {
		httpErr := httperror.InvalidContentType()
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)

	}

	// Ensure that the requesting entity can both authenticate to the SSH service, as well as
	// has authorization to access the Create Template endpoint
	storage := context.Get(r, "Storage").(backend.Storage)
	authHeader := r.Header.Get("Authorization")
	err := storage.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	err = storage.GetAccessControl().CreateSSHTemplate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	var newTemplate types.SSHTemplate
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&newTemplate)
	if err != nil {
		httpErr := httperror.RequestDecodeFail(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
	}
	httpErr := ssh.CreateSSHTemplate(newTemplate, storage)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
}

// ListSSHTemplatesHandler Handles the required logic to retrieve a SSH template list from the SSH service
// and passes it back via HTTP response
func ListSSHTemplatesHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")

	// Ensure that the requesting entity can both authenticate to the SSH service, as well as
	// has authorization to access the List Templates endpoint
	storage := context.Get(r, "Storage").(backend.Storage)
	err := storage.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	err = storage.GetAccessControl().ListSSHTemplates(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	templateList, httpErr := ssh.ListSSHTemplates(storage)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(templateList)
	if err != nil {
		httpErr := httperror.ResponseEncodeError(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
}

// GetSSHTemplateHandler Accepts the HTTP request with the desired SSH template name to be retrieved from
// the SSH service and passes it back via HTTP response
func GetSSHTemplateHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure that the requesting entity can both authenticate to the SSH service, then extract
	// the template name from the URI and test that it has authorization to access the
	// Get Template endpoint for the requested template
	storage := context.Get(r, "Storage").(backend.Storage)
	authHeader := r.Header.Get("Authorization")
	err := storage.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	templateName := mux.Vars(r)["templateName"]

	err = storage.GetAccessControl().ReadSSHTemplate(authHeader, templateName)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	template, httpErr := ssh.GetSSHTemplate(templateName, storage)

	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(template)
	if err != nil {
		httpErr := httperror.ResponseEncodeError(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
}

// ManageSSHTemplateHandler Accepts the HTTP request with the required information to update the data in
// the SSH template designated via `templateName`
func ManageSSHTemplateHandler(w http.ResponseWriter, r *http.Request) {
	if !pki.ValidateContentType(r.Header, "application/json") {
		httpErr := httperror.InvalidContentType()
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		httpErr := httperror.RequestDecodeFail(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	// Ensure that the requesting entity can both authenticate to the SSH service. 	Then parse the
	// request body first in order to get template name for authorization check to ensure the requstor
	// has authorization to access the Manage Template endpoint as well as the specific template
	storage := context.Get(r, "Storage").(backend.Storage)
	authHeader := r.Header.Get("Authorization")
	err = storage.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	var newTemplate types.SSHTemplate
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&newTemplate)
	if err != nil {
		httpErr := httperror.RequestDecodeFail(err.Error())
		http.Error(w, httpErr.JSON()+"   "+string(body), httpErr.HTTPResponse)
		return
	}
	err = storage.GetAccessControl().ManageSSHTemplate(authHeader, newTemplate.TemplateName)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	template, httpErr := ssh.GetSSHTemplate(newTemplate.TemplateName, storage)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	decoder = json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&template)
	if err != nil {
		httpErr := httperror.RequestDecodeFail(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	httpErr = ssh.DeleteSSHTemplate(template.TemplateName, storage)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	httpErr = ssh.CreateSSHTemplate(template, storage)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
}

// DeleteSSHTemplateHandler Accepts the HTTP request with the SSH template that is desired to be deleted
// and passes it to the SSH service
func DeleteSSHTemplateHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")

	// Ensure that the requesting entity can both authenticate to the SSH service, then extract
	// the template name from the URI and test that it has authorization to access the
	// Delete Template endpoint for the requested template
	storage := context.Get(r, "Storage").(backend.Storage)
	err := storage.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	templateName := mux.Vars(r)["templateName"]

	err = storage.GetAccessControl().DeleteSSHTemplate(authHeader, templateName)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	httpErr := ssh.DeleteSSHTemplate(templateName, storage)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

//CreateSSHCertificateHandler Accepts the HTTP request with all the required data to create a new SSH certificate
// and returns the newly created SSH certificate via HTTP response
func CreateSSHCertificateHandler(w http.ResponseWriter, r *http.Request) {
	if !pki.ValidateContentType(r.Header, "application/json") {
		httpErr := httperror.InvalidContentType()
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	// Ensure that the requesting entity can both authenticate to the SSH service, as well as
	// has authorization to access the Create Certificate endpoint using the requested template
	storage := context.Get(r, "Storage").(backend.Storage)
	authHeader := r.Header.Get("Authorization")
	err := storage.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		httpErr := httperror.InvalidAuthn(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	var certReq types.SSHSignRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&certReq)
	if err != nil {
		httpErr := httperror.RequestDecodeFail(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	err = storage.GetAccessControl().CreateSSHCertificate(authHeader, certReq.TemplateName)
	if err != nil {
		httpErr := httperror.InvalidAuthz(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}

	sshCert, httpErr := ssh.CreateSSHCertificate(certReq, storage)
	if httpErr != (httperror.HTTPError{}) {
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
		return
	}
	err = json.NewEncoder(w).Encode(sshCert)
	if err != nil {
		httpErr := httperror.ResponseEncodeError(err.Error())
		http.Error(w, httpErr.JSON(), httpErr.HTTPResponse)
	}
}
