package conjur

import (
	"fmt"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend"
)

// PolicyTemplates ...
type PolicyTemplates struct {
	newTemplate       string
	deleteTemplate    string
	newCertificate    string
	deleteCertificate string
	revokeCertificate string
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

func defaultRevokeCertificatePolicy() string {
	return `- !variable
  id: "<SerialNumber>"
  annotations:
    Revoked: <Revoked>
    RevocationDate: <RevocationDate>
    RevocationReasonCode: <RevocationReasonCode>
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
		defaultDeleteCertificatePolicy(),
		defaultRevokeCertificatePolicy())

	access := NewAccessFromDefaults(conjurClient.GetConfig(), defaultPolicyBranch())

	return NewConjurPki(conjurClient, defaultPolicyBranch(), policyTemplates, access), nil
}

// NewTemplates ...
func NewTemplates(newTemplate string, deleteTemplate string, newCertificate string, deleteCertificate string, revokedCertificate string) PolicyTemplates {
	return PolicyTemplates{
		newTemplate:       newTemplate,
		deleteTemplate:    deleteTemplate,
		newCertificate:    newCertificate,
		deleteCertificate: deleteCertificate,
		revokeCertificate: revokedCertificate,
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
