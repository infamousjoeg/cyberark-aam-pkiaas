package pki

import (
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/httperror"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// CreateTemplate -----------------------------------------------------
func CreateTemplate(newTemplate types.Template, backend backend.Storage) httperror.HTTPError {

	// Validate and sanitize all input from HTTP request

	err := ValidateKeyAlgoAndSize(newTemplate.KeyAlgo, newTemplate.KeyBits)
	if err != nil {
		return httperror.InvalidKeyAlgo(err.Error())
	}

	// Check for any errors returned from processing key usages and extended key usages
	// to validate they are all presented in proper format
	_, err = ProcessKeyUsages(newTemplate.KeyUsages)
	if err != nil {
		return httperror.InvalidKeyUsage(err.Error())
	}
	_, err = ProcessExtKeyUsages(newTemplate.ExtKeyUsages)
	if err != nil {
		return httperror.InvalidExtKeyUsage(err.Error())
	}

	//	err = ValidateTemplateDNS(newTemplate.PermDNSDomains, newTemplate.ExclDNSDomains)
	//	err = ValidateTemplateIP(newTemplate.PermIPRanges, newTemplate.ExclIPRanges)
	//	err = ValidateTemplateURI(newTemplate.PermURIDomains, newTemplate.ExclURIDomains)
	//	err = ValidateTemplateEmail(newTemplate.PermEmails, newTemplate.ExclEmails)

	// Validate any policy identifier OIDs that are sent in the request
	_, err = ProcessPolicyIdentifiers(newTemplate.PolicyIdentifiers)
	if err != nil {
		return httperror.InvalidPolicyID(err.Error())
	}
	// Store the newly created template object in the backend
	err = backend.CreateTemplate(newTemplate)
	if err != nil {
		return httperror.StorageWriteFail(err.Error())
	}
	return httperror.HTTPError{}
}

// DeleteTemplate --------------------------------------------------
func DeleteTemplate(templateName string, backend backend.Storage) httperror.HTTPError {
	err := backend.DeleteTemplate(templateName)
	if err != nil {
		return httperror.StorageDeleteFail(err.Error())
	}
	return httperror.HTTPError{}
}

// GetTemplate -------------------------------------------------------
func GetTemplate(templateName string, backend backend.Storage) (types.Template, httperror.HTTPError) {
	template, err := backend.GetTemplate(templateName)

	if err != nil {
		httpErr := httperror.StorageReadFail(err.Error())
		return types.Template{}, httpErr
	}

	return template, httperror.HTTPError{}
}

// ListTemplate ------------------------------------
func ListTemplate(backend backend.Storage) (types.TemplateListResponse, httperror.HTTPError) {
	templates, err := backend.ListTemplates()
	if err != nil {
		return types.TemplateListResponse{}, httperror.StorageReadFail(err.Error())
	}
	respTemplates := types.TemplateListResponse{
		Templates: templates,
	}

	return respTemplates, httperror.HTTPError{}
}
