package conjur

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

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
func (c ConjurPki) CreateTemplate(template types.Template) error {
	variableID := c.getTemplatePolicyBranch() + "/" + template.TemplateName

	// validate template does not exists
	_, err := c.client.RetrieveSecret(variableID)
	if err == nil {
		return fmt.Errorf("Template '%s' already exists", template.TemplateName)
	}

	// Template name cannot contain a '/'
	if strings.Contains(template.TemplateName, "/") {
		return fmt.Errorf("Template name '%s' is invalid because it contains a '/'", template.TemplateName)
	}

	// replace template placeholders
	newTemplatePolicy := bytes.NewReader([]byte(
		ReplaceTemplate(template, c.templates.newTemplate)))

	// cast the template stuct into json
	templateJSON, err := json.Marshal(template)
	if err != nil {
		return err
	}

	// Load policy to create the variable
	response, err := c.client.LoadPolicy(
		conjurapi.PolicyModePatch,
		c.getTemplatePolicyBranch(),
		newTemplatePolicy,
	)
	if err != nil {
		return fmt.Errorf("Failed to create template when loading policy. Message '%v'. %s", response, err)
	}

	// Set the Secret value
	err = c.client.AddSecret(variableID, string(templateJSON))
	return err
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
func (c ConjurPki) DeleteTemplate(templateName string) error {
	// validate template resource exists
	variableID := c.getTemplatePolicyBranch() + "/" + templateName
	_, err := c.client.RetrieveSecret(variableID)
	if err != nil {
		return fmt.Errorf("Failed to retrieve template with id '%s'. %s", variableID, err)
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
		return fmt.Errorf("Failed to delete template with id '%s'. Message: '%v'. %s", variableID, response, err)
	}

	return err
}

// CreateCertificate ...
func (c ConjurPki) CreateCertificate(cert types.CreateCertificateInDap) error {
	variableID := c.getCertificatePolicyBranch() + "/" + cert.SerialNumber

	// validate cert does not exists
	_, err := c.client.RetrieveSecret(variableID)
	if err == nil {
		return fmt.Errorf("Certificate '%s' already exists", cert.SerialNumber)
	}
	return c.updateCertificate(cert)

}

func (c ConjurPki) updateCertificate(cert types.CreateCertificateInDap) error {

	variableID := c.getCertificatePolicyBranch() + "/" + cert.SerialNumber
	// replace template placeholders
	newPolicy := bytes.NewReader([]byte(ReplaceCertificate(cert, c.templates.newCertificate)))

	// Load policy to create the variable
	response, err := c.client.LoadPolicy(
		conjurapi.PolicyModePatch,
		c.getCertificatePolicyBranch(),
		newPolicy,
	)

	if err != nil {
		return fmt.Errorf("Failed to load policy for creating certificate. Message '%v'. %s", response, err)
	}

	// Set the Secret value
	// If certificate value is not provided assume we are
	// just updating the certificate variable annotations
	if cert.Certificate != "" {
		err = c.client.AddSecret(variableID, cert.Certificate)
	}
	return err
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
	value, err := c.client.RetrieveSecret(variableID)

	if err != nil {
		return "", fmt.Errorf("Failed to retrieve certificate with serial number '%s'. %s", variableID, err)
	}

	return string(value), err
}

// DeleteCertificate ...
func (c ConjurPki) DeleteCertificate(serialNumber *big.Int) error {
	// validate template resource exists
	variableID := c.getCertificatePolicyBranch() + "/" + serialNumber.String()
	_, err := c.client.RetrieveSecret(variableID)
	if err != nil {
		return fmt.Errorf("Failed to retrieve certificate with serial number '%s'. %s", variableID, err)
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
		return fmt.Errorf("Failed to delete template with id '%s'. Message: '%v'. %s", variableID, response, err)
	}

	return err
}

// GetCAChain ...
func (c ConjurPki) GetCAChain() ([]string, error) {
	variableID := c.getCAChainVariableID()
	caChain := &[]string{}

	value, err := c.client.RetrieveSecret(variableID)
	if err != nil {
		return *caChain, fmt.Errorf("Failed to retrieve certificate chain with variable id '%s'. %s", variableID, err)
	}

	err = json.Unmarshal(value, caChain)
	if err != nil {
		return *caChain, fmt.Errorf("Failed to unmarshal certificate chain. %s", err)
	}

	return *caChain, nil
}

// WriteCAChain ...
func (c ConjurPki) WriteCAChain(certBundle []string) error {
	variableID := c.getCAChainVariableID()

	certBundleJSON, err := json.Marshal(certBundle)
	if err != nil {
		return fmt.Errorf("Failed to marshal cert bundle. %s", err)
	}

	err = c.client.AddSecret(variableID, string(certBundleJSON))
	if err != nil {
		return fmt.Errorf("Failed to set certificate chain with variable id '%s'. %s", variableID, err)
	}

	return nil
}

// GetSigningCert ...
func (c ConjurPki) GetSigningCert() (string, error) {
	variableID := c.getSigningCertVariableID()

	value, err := c.client.RetrieveSecret(variableID)
	if err != nil {
		return "", fmt.Errorf("Failed to retrieve signing certificate with variable id '%s'. %s", variableID, err)
	}

	return string(value), nil
}

// WriteSigningCert ...
func (c ConjurPki) WriteSigningCert(content string) error {
	variableID := c.getSigningCertVariableID()

	err := c.client.AddSecret(variableID, content)
	if err != nil {
		return fmt.Errorf("Failed to set signing certificate with variable id '%s'. %s", variableID, err)
	}

	return nil
}

// GetSigningKey ...
func (c ConjurPki) GetSigningKey() (string, error) {
	variableID := c.getSigningKeyVariableID()

	value, err := c.client.RetrieveSecret(variableID)
	if err != nil {
		return "", fmt.Errorf("Failed to retrieve signing key with variable id '%s'. %s", variableID, err)
	}

	return string(value), nil
}

// WriteSigningKey ...
func (c ConjurPki) WriteSigningKey(content string) error {
	variableID := c.getSigningKeyVariableID()

	err := c.client.AddSecret(variableID, content)
	if err != nil {
		return fmt.Errorf("Failed to set signing key with variable id '%s'. %s", variableID, err)
	}

	return nil
}

// GetCRL ...
func (c ConjurPki) GetCRL() (string, error) {
	variableID := c.getCRLVariableID()

	value, err := c.client.RetrieveSecret(variableID)
	if err != nil {
		return "", fmt.Errorf("Failed to retrieve CRL with variable id '%s'. %s", variableID, err)
	}

	return string(value), nil
}

// WriteCRL ...
func (c ConjurPki) WriteCRL(content string) error {
	variableID := c.getCRLVariableID()

	err := c.client.AddSecret(variableID, content)
	if err != nil {
		return fmt.Errorf("Failed to set CRL with variable id '%s'. %s", variableID, err)
	}

	return nil
}

// RevokeCertificate ...
func (c ConjurPki) RevokeCertificate(serialNumber *big.Int, reasonCode int, revocationDate time.Time) error {

	variableID := c.getCertificatePolicyBranch() + "/" + serialNumber.String()
	_, err := c.client.RetrieveSecret(variableID)

	if err != nil {
		return fmt.Errorf("Failed to revoked certificate with ID '%s'. %s", variableID, err)
	}

	certificateInDap := types.CreateCertificateInDap{
		SerialNumber:         serialNumber.String(),
		Revoked:              true,
		RevocationDate:       fmt.Sprintf("%v", revocationDate.Unix()),
		RevocationReasonCode: reasonCode,
		InternalState:        "revoked",
	}

	err = c.updateCertificate(certificateInDap)

	return err
}

// GetRevokedCerts ...
func (c ConjurPki) GetRevokedCerts() ([]types.RevokedCertificate, error) {
	filter := &conjurapi.ResourceFilter{
		Kind:   "variable",
		Search: "csasarevokedcsasa",
	}

	revokedCerts := []types.RevokedCertificate{}

	resources, err := c.client.Resources(filter)
	if err != nil {
		err = fmt.Errorf("Failed to list resources when attempting to get revoked certificates. %s", err)
		return revokedCerts, err
	}

	for _, resource := range resources {
		id := resource["id"].(string)
		_, _, id = SplitConjurID(id)
		parts := strings.Split(id, "/")
		templatesRoot := parts[len(parts)-2]

		if templatesRoot == "certificates" {
			serialNumberString := parts[len(parts)-1]
			reasonCode, err := GetAnnotationValue(resource, "RevocationReasonCode")
			if err != nil {
				return revokedCerts, fmt.Errorf("Failed to retrieve RevocationReasonCode from certificate '%s'. %s", serialNumberString, err)
			}

			revocationDate, err := GetAnnotationValue(resource, "RevocationDate")
			if err != nil {
				return revokedCerts, fmt.Errorf("Failed to retrieve RevocationDate from certificate '%s'. %s", serialNumberString, err)
			}

			reasonCodeInt, err := strconv.Atoi(reasonCode)
			if err != nil {
				return revokedCerts, fmt.Errorf("Failed to cast RevocationReasonCode '%s' into an int", reasonCode)
			}

			revocationDateInt, err := strconv.Atoi(revocationDate)
			if err != nil {
				return revokedCerts, fmt.Errorf("Failed to cast RevocationDate '%s' into an int", revocationDate)
			}

			dateTime := time.Unix(int64(revocationDateInt), 0)

			revokedCert := types.RevokedCertificate{
				SerialNumber:   serialNumberString,
				ReasonCode:     reasonCodeInt,
				RevocationDate: dateTime,
			}

			revokedCerts = append(revokedCerts, revokedCert)
		}
	}

	return revokedCerts, nil
}
