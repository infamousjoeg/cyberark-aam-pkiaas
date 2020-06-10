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
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// PolicyTemplates ...
type PolicyTemplates struct {
	newTemplate       string
	deleteTemplate    string
	newCertificate    string
	deleteCertificate string
}

// StorageBackend ...
type StorageBackend struct {
	client       *conjurapi.Client
	policyBranch string
	templates    PolicyTemplates
	Access       AccessControl
}

// GetAccessControl -----
func (c StorageBackend) GetAccessControl() backend.Access {
	return backend.Access(c.Access)
}

func (c StorageBackend) getTemplatePolicyBranch() string {
	return c.policyBranch + "/templates"
}

func (c StorageBackend) getCertificatePolicyBranch() string {
	return c.policyBranch + "/certificates"
}

func (c StorageBackend) getCAChainVariableID() string {
	return c.policyBranch + "/ca/chain"
}

func (c StorageBackend) getSigningCertVariableID() string {
	return c.policyBranch + "/ca/cert"
}

func (c StorageBackend) getSigningKeyVariableID() string {
	return c.policyBranch + "/ca/key"
}

func (c StorageBackend) getCRLVariableID() string {
	return c.policyBranch + "/crl"
}

func defaultConjurClient() (*conjurapi.Client, error) {
	config, err := conjurapi.LoadConfig()
	if err != nil {
		fmt.Printf("Failed to init config from environment variables. %s", err.Error())
		return nil, fmt.Errorf("Failed to init config from environment variables. %s", err)
	}
	client, err := conjurapi.NewClientFromEnvironment(config)
	if err != nil {
		fmt.Printf("Failed to init client from config. %s", err.Error())
		return nil, fmt.Errorf("Failed to init client from config. %s", err)
	}
	return client, err
}

func defaultCreateTemplatePolicy() string {
	return `- !variable
  id: <TemplateName>
`
}

func defaultCreateCertificatePolicy() string {
	return `- !variable
  id: "<SerialNumber>"
  annotations:
    Revoked: <Revoked>
    RevocationDate: <RevocationDate>
    RevocationReasonCode: <RevocationReasonCode>
    ExpirationDate: <ExpirationDate>
    InternalState: csasa<InternalState>csasa
`
}

func defaultDeleteTemplatePolicy() string {
	return `- !delete
  record: !variable <TemplateName>
`
}

func defaultDeleteCertificatePolicy() string {
	return `- !delete
  record: !variable <SerialNumber>
`
}

func defaultPolicyBranch() string {
	return "pki"
}

// NewFromDefaults ---
func NewFromDefaults() (StorageBackend, error) {
	conjurClient, err := defaultConjurClient()
	if err != nil {
		return StorageBackend{}, fmt.Errorf("Failed to init Conjur client: %s", err)
	}

	policyTemplates := NewTemplates(
		defaultCreateTemplatePolicy(),
		defaultDeleteTemplatePolicy(),
		defaultCreateCertificatePolicy(),
		defaultDeleteCertificatePolicy())

	access := NewAccessFromDefaults(conjurClient.GetConfig(), defaultPolicyBranch())

	return NewConjurPki(conjurClient, defaultPolicyBranch(), policyTemplates, access), nil
}

// NewTemplates ...
func NewTemplates(newTemplate string, deleteTemplate string, newCertificate string, deleteCertificate string) PolicyTemplates {
	return PolicyTemplates{
		newTemplate:       newTemplate,
		deleteTemplate:    deleteTemplate,
		newCertificate:    newCertificate,
		deleteCertificate: deleteCertificate,
	}
}

// NewConjurPki ...
func NewConjurPki(client *conjurapi.Client, policyBranch string, templates PolicyTemplates, access AccessControl) StorageBackend {
	return StorageBackend{
		client:       client,
		policyBranch: policyBranch,
		templates:    templates,
		Access:       access,
	}
}

// CreateTemplate ...
func (c StorageBackend) CreateTemplate(template types.Template) error {
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
func (c StorageBackend) ListTemplates() ([]string, error) {
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
func (c StorageBackend) GetTemplate(templateName string) (types.Template, error) {
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
func (c StorageBackend) DeleteTemplate(templateName string) error {
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
func (c StorageBackend) CreateCertificate(cert types.CreateCertificateData) error {
	variableID := c.getCertificatePolicyBranch() + "/" + cert.SerialNumber

	// validate cert does not exists
	_, err := c.client.RetrieveSecret(variableID)
	if err == nil {
		return fmt.Errorf("Certificate '%s' already exists", cert.SerialNumber)
	}
	return c.updateCertificate(cert)

}

func (c StorageBackend) updateCertificate(cert types.CreateCertificateData) error {

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
func (c StorageBackend) ListCertificates() ([]*big.Int, error) {
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
func (c StorageBackend) GetCertificate(serialNumber *big.Int) (string, error) {
	variableID := c.getCertificatePolicyBranch() + "/" + serialNumber.String()
	value, err := c.client.RetrieveSecret(variableID)

	if err != nil {
		return "", fmt.Errorf("Failed to retrieve certificate with serial number '%s'. %s", variableID, err)
	}

	return string(value), err
}

// DeleteCertificate ...
func (c StorageBackend) DeleteCertificate(serialNumber *big.Int) error {
	// validate template resource exists
	variableID := c.getCertificatePolicyBranch() + "/" + serialNumber.String()
	_, err := c.client.RetrieveSecret(variableID)
	if err != nil {
		return fmt.Errorf("Failed to retrieve certificate with serial number '%s'. %s", variableID, err)
	}

	// remove the template resource
	certificate := types.CreateCertificateData{
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
func (c StorageBackend) GetCAChain() ([]string, error) {
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
func (c StorageBackend) WriteCAChain(certBundle []string) error {
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
func (c StorageBackend) GetSigningCert() (string, error) {
	variableID := c.getSigningCertVariableID()

	value, err := c.client.RetrieveSecret(variableID)
	if err != nil {
		return "", fmt.Errorf("Failed to retrieve signing certificate with variable id '%s'. %s", variableID, err)
	}

	return string(value), nil
}

// WriteSigningCert ...
func (c StorageBackend) WriteSigningCert(content string) error {
	variableID := c.getSigningCertVariableID()

	err := c.client.AddSecret(variableID, content)
	if err != nil {
		return fmt.Errorf("Failed to set signing certificate with variable id '%s'. %s", variableID, err)
	}

	return nil
}

// GetSigningKey ...
func (c StorageBackend) GetSigningKey() (string, error) {
	variableID := c.getSigningKeyVariableID()

	value, err := c.client.RetrieveSecret(variableID)
	if err != nil {
		return "", fmt.Errorf("Failed to retrieve signing key with variable id '%s'. %s", variableID, err)
	}

	return string(value), nil
}

// WriteSigningKey ...
func (c StorageBackend) WriteSigningKey(content string) error {
	variableID := c.getSigningKeyVariableID()

	err := c.client.AddSecret(variableID, content)
	if err != nil {
		return fmt.Errorf("Failed to set signing key with variable id '%s'. %s", variableID, err)
	}

	return nil
}

// GetCRL ...
func (c StorageBackend) GetCRL() (string, error) {
	variableID := c.getCRLVariableID()

	value, err := c.client.RetrieveSecret(variableID)
	if err != nil {
		return "", fmt.Errorf("Failed to retrieve CRL with variable id '%s'. %s", variableID, err)
	}

	return string(value), nil
}

// WriteCRL ...
func (c StorageBackend) WriteCRL(content string) error {
	variableID := c.getCRLVariableID()

	err := c.client.AddSecret(variableID, content)
	if err != nil {
		return fmt.Errorf("Failed to set CRL with variable id '%s'. %s", variableID, err)
	}

	return nil
}

// RevokeCertificate ...
func (c StorageBackend) RevokeCertificate(serialNumber *big.Int, reasonCode int, revocationDate time.Time) error {

	variableID := c.getCertificatePolicyBranch() + "/" + serialNumber.String()
	_, err := c.client.RetrieveSecret(variableID)

	if err != nil {
		return fmt.Errorf("Failed to revoked certificate with ID '%s'. %s", variableID, err)
	}

	certificateInDap := types.CreateCertificateData{
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
func (c StorageBackend) GetRevokedCerts() ([]types.RevokedCertificate, error) {
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
