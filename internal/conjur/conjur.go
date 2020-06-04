package conjur

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// Content of the templates being used
type ConjurTemplates struct {
	newTemplate       string
	deleteTemplate    string
	newCertificate    string
	deleteCertificate string
}

type ConjurPki struct {
	client       *conjurapi.Client
	policyBranch string
	templates    ConjurTemplates
}

func (c ConjurPki) getTemplatePolicyBranch() string {
	return c.policyBranch + "/templates"
}

func (c ConjurPki) getCertificatePolicyBranch() string {
	return c.policyBranch + "/certificates"
}

func (c ConjurPki) getCAChainVariableID() string {
	return c.policyBranch + "/ca/chain"
}

func (c ConjurPki) getSigningCertVariableID() string {
	return c.policyBranch + "/ca/cert"
}

func (c ConjurPki) getSigningKeyVariableID() string {
	return c.policyBranch + "/ca/key"
}

func (c ConjurPki) getCRLVariableID() string {
	return c.policyBranch + "/crl"
}



// NewTemplates ...
func NewTemplates(newTemplate string, deleteTemplate string, newCertificate string, deleteCertificate string) ConjurTemplates {
	return ConjurTemplates{
		newTemplate:       newTemplate,
		deleteTemplate:    deleteTemplate,
		newCertificate:    newCertificate,
		deleteCertificate: deleteCertificate,
	}
}

// NewConjurPki ...
func NewConjurPki(client *conjurapi.Client, policyBranch string, templates ConjurTemplates) ConjurPki {
	return ConjurPki{
		client:       client,
		policyBranch: policyBranch,
		templates:    templates,
	}
}



// CreateTemplate ...
func (c ConjurPki) CreateTemplate(template types.Template) (*conjurapi.PolicyResponse, error) {
	variableID := c.getTemplatePolicyBranch() + "/" + template.TemplateName

	// validate template does not exists
	_, err := c.client.RetrieveSecret(variableID)
	if err == nil {
		return nil, fmt.Errorf("Template '%s' already exists", template.TemplateName)
	}

	// Template name cannot contain a '/'
	if strings.Contains(template.TemplateName, "/") {
		return nil, fmt.Errorf("Template name '%s' is invalid because it contains a '/'", template.TemplateName)
	}

	// replace template placeholders
	newTemplatePolicy := bytes.NewReader([]byte(
		ReplaceTemplate(template, c.templates.newTemplate)))

	// cast the template stuct into json
	templateJSON, err := json.Marshal(template)
	if err != nil {
		return nil, err
	}

	// Load policy to create the variable
	response, err := c.client.LoadPolicy(
		conjurapi.PolicyModePatch,
		c.getTemplatePolicyBranch(),
		newTemplatePolicy,
	)
	if err != nil {
		return response, err
	}

	// Set the Secret value
	err = c.client.AddSecret(variableID, string(templateJSON))
	return response, err
}

// ListTemplates ...
func (c ConjurPki) ListTemplates() ([]string, error) {
	filter := &conjurapi.ResourceFilter{
		Kind:   "variable",
		Search: "templates",
	}
	var templateNames []string

	// List resources to get templates
	resources, err := ListResources(c.client, filter)
	if err != nil {
		return templateNames, err
	}

	// Parse the template name for all of the template variables
	for _, resource := range resources {
		_, _, id := SplitConjurID(resource)
		fmt.Printf("My id: %s", id)
		parts := strings.Split(id, "/")
		templatesRoot := parts[len(parts)-2]
		if templatesRoot == "templates" {
			name := parts[len(parts)-1]
			templateNames = append(templateNames, name)
		}
	}

	return templateNames, err
}

// GetTemplate ...
func (c ConjurPki) GetTemplate(templateName string) (types.Template, error) {
	variableID := c.getTemplatePolicyBranch() + "/" + templateName
	templateJSON, err := c.client.RetrieveSecret(variableID)
	template := &types.Template{}

	if err != nil {
		return *template, fmt.Errorf("Failed to retrieve template with id '%s'. %s", variableID, err)
	}

	err = json.Unmarshal(templateJSON, template)
	if err != nil {
		return *template, fmt.Errorf("Failed to cast '%s' into types.Template. %s", string(templateJSON), err)
	}

	return *template, err
}

// DeleteTemplate ...
func (c ConjurPki) DeleteTemplate(templateName string) (*conjurapi.PolicyResponse, error) {
	// validate template resource exists
	variableID := c.getTemplatePolicyBranch() + "/" + templateName
	_, err := c.client.RetrieveSecret(variableID)
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve template with id '%s'. %s", variableID, err)
	}

	// remove the template resource
	template := types.Template{
		TemplateName: templateName,
	}
	deleteTemplatePolicy := bytes.NewReader([]byte(
		ReplaceTemplate(template, c.templates.deleteTemplate)))
	response, err := c.client.LoadPolicy(
		conjurapi.PolicyModePatch,
		c.getTemplatePolicyBranch(),
		deleteTemplatePolicy,
	)
	if err != nil {
		return response, fmt.Errorf("Failed to delete template with id '%s'. %s", variableID, err)
	}

	return response, err
}



// CreateCertificate ...
func (c ConjurPki) CreateCertificate(cert types.CreateCertificateInDap) (*conjurapi.PolicyResponse, error) {
	variableID := c.getCertificatePolicyBranch() + "/" + cert.SerialNumber

	// validate cert does not exists
	_, err := c.client.RetrieveSecret(variableID)
	if err == nil {
		return nil, fmt.Errorf("Certificate '%s' already exists", cert.SerialNumber)
	}

	// replace template placeholders
	newPolicy := bytes.NewReader([]byte(ReplaceCertificate(cert, c.templates.newCertificate)))

	// cast the template stuct into json
	certificateJSON, err := json.Marshal(cert)
	if err != nil {
		return nil, err
	}

	// Load policy to create the variable
	response, err := c.client.LoadPolicy(
		conjurapi.PolicyModePatch,
		c.getCertificatePolicyBranch(),
		newPolicy,
	)

	if err != nil {
		return response, err
	}

	// Set the Secret value
	err = c.client.AddSecret(variableID, string(certificateJSON))
	return response, err
}

// ListCertificates ...
func (c ConjurPki) ListCertificates() ([]*big.Int, error) {
	filter := &conjurapi.ResourceFilter{
		Kind:   "variable",
		Search: "certificates",
	}

	var certficateSerialNumbers []*big.Int

	// List resources to get templates
	resources, err := ListResources(c.client, filter)
	if err != nil {
		return certficateSerialNumbers, err
	}

	// Parse the template name for all of the template variables
	for _, resource := range resources {
		_, _, id := SplitConjurID(resource)
		parts := strings.Split(id, "/")
		templatesRoot := parts[len(parts)-2]
		if templatesRoot == "certificates" {
			serialNumberString := parts[len(parts)-1]
			// NOTE: I don't really know what the 10 does at then end of the SetString() function
			serialNumber, ok := new(big.Int).SetString(serialNumberString, 10)
			if ok {
				certficateSerialNumbers = append(certficateSerialNumbers, serialNumber)
			} else {
				// If we failed to cast then return an error
				return certficateSerialNumbers, fmt.Errorf("Failed to cast serial number '%s' into type big.Int", serialNumberString)
			}

		}
	}

	return certficateSerialNumbers, err
}

// GetCertificate ...
func (c ConjurPki) GetCertificate(serialNumber *big.Int) (string, error) {
	variableID := c.getCertificatePolicyBranch() + "/" + serialNumber.String()
	certificateJSON, err := c.client.RetrieveSecret(variableID)

	if err != nil {
		return "", fmt.Errorf("Failed to retrieve certificate with serial number '%s'. %s", variableID, err)
	}

	certificate := &types.CreateCertificateInDap{}
	err = json.Unmarshal(certificateJSON, certificate)

	return string(certificate.Certificate), err
}

// DeleteCertificate ...
func (c ConjurPki) DeleteCertificate(serialNumber *big.Int) (*conjurapi.PolicyResponse, error) {
	// validate template resource exists
	variableID := c.getCertificatePolicyBranch() + "/" + serialNumber.String()
	_, err := c.client.RetrieveSecret(variableID)
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve certificate with serial number '%s'. %s", variableID, err)
	}

	// remove the template resource
	certificate := types.CreateCertificateInDap{
		SerialNumber: serialNumber.String(),
	}
	deleteCertPolicy := bytes.NewReader([]byte(
		ReplaceCertificate(certificate, c.templates.deleteCertificate)))

	response, err := c.client.LoadPolicy(
		conjurapi.PolicyModePatch,
		c.getCertificatePolicyBranch(),
		deleteCertPolicy,
	)
	if err != nil {
		return response, fmt.Errorf("Failed to delete template with id '%s'. %s", variableID, err)
	}

	return response, err
}



// GetCAChain ...
func (c ConjurPki) GetCAChain() (string, error) [
	variableID := getCAChainVariableID()

	value, err := c.client.RetrieveSecret(variableID)
	if err != nil {
		return "", fmt.Errorf("Failed to retrieve certificate chain with variable id '%s'. %s", variableID, err)
	}

	return string(value)
}

// WriteCAChain ...
func (c ConjurPki) WriteCAChain(content string) (string, error) [
	variableID := getCAChainVariableID()

	value, err := c.client.AddSecret(variableID, content)
	if err != nil {
		return "", fmt.Errorf("Failed to set certificate chain with variable id '%s'. %s", variableID, err)
	}

	return string(value)
}

// GetSigningCert ...
func (c ConjurPki) GetSigningCert() (string, error) [
	variableID := getSigningCertVariableID()

	value, err := c.client.RetrieveSecret(variableID)
	if err != nil {
		return "", fmt.Errorf("Failed to retrieve signing certificate with variable id '%s'. %s", variableID, err)
	}

	return string(value), err
}

// WriteSigningCert ...
func (c ConjurPki) WriteSigningCert(content string) (string, error) [
	variableID := getSigningCertVariableID()

	value, err := c.client.AddSecret(variableID, content)
	if err != nil {
		return "", fmt.Errorf("Failed to set signing certificate with variable id '%s'. %s", variableID, err)
	}

	return string(value), err
}

// GetSigningKey ...
func (c ConjurPki) GetSigningKey() (string, error) [
	variableID := getSigningKeyVariableID()

	value, err := c.client.RetrieveSecret(variableID)
	if err != nil {
		return "", fmt.Errorf("Failed to retrieve signing key with variable id '%s'. %s", variableID, err)
	}

	return string(value), err
}

// WriteSigningKey ...
func (c ConjurPki) WriteSigningKey(content string)) (string, error) [
	variableID := getSigningKeyVariableID()

	value, err := c.client.AddSecret(variableID, content)
	if err != nil {
		return "", fmt.Errorf("Failed to set signing key with variable id '%s'. %s", variableID, err)
	}

	return string(value), err
}


// GetCRL ...
func (c ConjurPki) GetCRL() (string, error) [
	variableID := getCRLVariableID()

	value, err := c.client.RetrieveSecret(variableID)
	if err != nil {
		return "", fmt.Errorf("Failed to retrieve CRL with variable id '%s'. %s", variableID, err)
	}

	return string(value), err
}

// WriteCRL ...
func (c ConjurPki) WriteCRL(content string)) (string, error) [
	variableID := getCRLVariableID()

	value, err := c.client.AddSecret(variableID, content)
	if err != nil {
		return "", fmt.Errorf("Failed to set CRL with variable id '%s'. %s", variableID, err)
	}

	return string(value), err
}
