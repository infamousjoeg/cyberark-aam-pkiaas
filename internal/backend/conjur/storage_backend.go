package conjur

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/pkg/log"
)

// Role of conjur instance. Should be master or follower
type Role string

const (
	// Master conjur appliance
	master Role = "master"
	// Follower conjur appliance
	follower Role = "follower"
)

// PolicyTemplates ...
type PolicyTemplates struct {
	newTemplate       string
	deleteTemplate    string
	newCertificate    string
	deleteCertificate string
	revokeCertificate string
	newSSHTemplate    string
	deleteSSHTemplate string
}

// StorageBackend ...
type StorageBackend struct {
	client       *conjurapi.Client
	policyBranch string
	templates    PolicyTemplates
	role         Role
	Access       AccessControl
}

// GetAccessControl -----
func (c StorageBackend) GetAccessControl() backend.Access {
	return backend.Access(c.Access)
}

// InitConfig This will init the policy in the 'pki' webservice
func (c StorageBackend) InitConfig() error {
	if c.role == master {
		pkiPolicy := getInitConfigPolicy()
		response, err := c.client.LoadPolicy(conjurapi.PolicyModePatch, c.policyBranch, pkiPolicy)
		if err != nil {
			return fmt.Errorf("Failed to initialize configuration for the PKI service. %v. %s", response, err)
		}
	}
	return nil
}

func getInitConfigPolicy() io.Reader {
	return bytes.NewReader([]byte(`
- !webservice
- !variable ca/cert
- !variable ca/key
- !variable ca/cert-chain
- !variable crl

# higher level groups
- !group admin
- !group audit
- !group authenticate

- &admins
  - !group templates-admin
  - !group certificates-admin
  - !group purge-admin
  - !group ca-admin
  - !group ssh-templates-admin
  - !group ssh-certificates-admin

 # endpoint permission groups
- &templates
  - !group list-templates
  - !group read-templates
  - !group create-templates
  - !group manage-templates
  - !group delete-templates
- &certificates
  - !group list-certificates
  - !group read-certificates
  - !group create-certificates
  - !group sign-certificates
  - !group revoke-certificates
- &purge
  - !group purge
  - !group purge-crl
- &ca
  - !group set-ca-chain
  - !group set-ca-signing-key
  - !group set-ca-signing-cert
  - !group generate-intermediate-csr
- &sshTemplates
  - !group list-ssh-templates
  - !group read-ssh-templates
  - !group create-ssh-templates
  - !group manage-ssh-templates
  - !group delete-ssh-templates
- &sshCertificates
  - !group create-ssh-certificates

- !permit
  role: !group authenticate
  resource: !webservice
  privileges:
  - authenticate

- !permit
  role: !group list-ssh-templates
  resource: !webservice
  privileges:
  - list-ssh-templates

- !permit
  role: !group create-ssh-templates
  resource: !webservice
  privileges:
  - create-ssh-templates

- !permit
  role: !group list-templates
  resource: !webservice
  privileges:
  - list-templates

- !permit
  role: !group create-templates
  resource: !webservice
  privileges:
  - create-templates

- !permit
  role: !group list-certificates
  resource: !webservice
  privileges:
  - list-certificates

- !permit
  role: !group purge
  resource: !webservice
  privileges:
  - purge

- !permit
  role: !group purge-crl
  resource: !webservice
  privileges:
  - purge-crl

- !permit
  role: !group set-ca-chain
  resource: !webservice
  privileges:
  - set-ca-chain

- !permit
  role: !group set-ca-signing-key
  resource: !webservice
  privileges:
  - set-ca-signing-key

- !permit
  role: !group set-ca-signing-cert
  resource: !webservice
  privileges:
  - set-ca-signing-cert

- !permit
  role: !group generate-intermediate-csr
  resource: !webservice
  privileges:
  - generate-intermediate-csr

- !grant
  roles: *templates
  member: !group templates-admin

- !grant
  roles: *certificates
  member: !group certificates-admin

- !grant
  roles: *sshTemplates
  member: !group ssh-templates-admin

- !grant
  roles: *sshCertificates
  member: !group ssh-certificates-admin

- !grant
  roles: *purge
  member: !group purge-admin

- !grant
  roles: *ca
  member: !group ca-admin

- !grant
  roles: *admins
  member: !group admin

- !grant
  role: !group authenticate
  members:
  - !group admin
  - !group ca-admin
  - !group purge-admin
  - !group certificates-admin
  - !group templates-admin

- !grant
  roles:
  - !group list-templates
  - !group list-certificates
  - !group list-ssh-templates
  - !group read-templates
  - !group read-certificates
  - !group read-ssh-templates
  member: !group audit

- !grant
  roles:
  - !group list-certificates
  - !group read-certificates
  member: !group authenticate
 `))
}

func (c StorageBackend) getTemplatePolicyBranch() string {
	return c.policyBranch
}

func (c StorageBackend) getTemplateVariableID(templateName string) string {
	return c.policyBranch + "/templates/" + templateName
}

func (c StorageBackend) getSSHTemplateVariableID(templateName string) string {
	return c.policyBranch + "/ssh-templates/" + templateName
}

func (c StorageBackend) getCertificatePolicyBranch() string {
	return c.policyBranch
}

func (c StorageBackend) getCertificateVariableID(serialNumber string) string {
	return c.policyBranch + "/certificates/" + serialNumber
}

func (c StorageBackend) getCAChainVariableID() string {
	return c.policyBranch + "/ca/cert-chain"
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

func getApplianceRole(client *conjurapi.Client) (Role, error) {
	infoEndpoint := fmt.Sprintf("%s/info", client.GetConfig().ApplianceURL)
	resp, err := client.GetHttpClient().Get(infoEndpoint)
	if err != nil {
		return "", fmt.Errorf("Failed to retrieve info from the conjur appliance. %s", err)
	}

	var respBody map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return "", fmt.Errorf("Failed to unmarshal info from conjur appliance. %s", err)
	}

	role, ok := respBody["role"].(string)
	if !ok {
		return "", fmt.Errorf("Failed to parse role from conjur appliance")
	}

	if role == string(master) {
		return master, nil
	} else if role == string(follower) {
		return follower, nil
	}

	return "", fmt.Errorf("Failed to identify role. '%s' is an invalid role", role)
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
	return client, nil
}

// NewDefaultConjurClient return the default conjur client
func NewDefaultConjurClient() (*conjurapi.Client, error) {
	return defaultConjurClient()
}

func defaultCreateTemplatePolicy() string {
	return `- !variable
  id: templates/<TemplateName>

# groups related to the privileges
- !group templates/<TemplateName>-read
- !group templates/<TemplateName>-manage
- !group templates/<TemplateName>-delete
- !group templates/<TemplateName>-create-certificates
- !group templates/<TemplateName>-sign-certificates

# assign the privileges to the groups above
- !permit
  role: !group templates/<TemplateName>-read
  resource: !webservice
  privileges:
  - read-template-<TemplateName>

- !permit
  role: !group templates/<TemplateName>-manage
  resource: !webservice
  privileges:
  - manage-template-<TemplateName>

- !permit
  role: !group templates/<TemplateName>-delete
  resource: !webservice
  privileges:
  - delete-template-<TemplateName>

- !permit
  role: !group templates/<TemplateName>-create-certificates
  resource: !webservice
  privileges:
  - create-certificate-from-<TemplateName>

- !permit
  role: !group templates/<TemplateName>-sign-certificates
  privileges:
  - sign-certificate-from-<TemplateName>



# grant the groups accordingly
- !grant
  role: !group templates/<TemplateName>-read
  member: !group read-templates

- !grant
  role: !group templates/<TemplateName>-manage
  member: !group manage-templates

- !grant
  role: !group templates/<TemplateName>-delete
  member: !group delete-templates

- !grant
  role: !group templates/<TemplateName>-create-certificates
  member: !group create-certificates

- !grant
  role: !group templates/<TemplateName>-sign-certificates
  member: !group sign-certificates
`
}

func defaultCreateCertificatePolicy() string {
	return `- !variable
  id: certificates/<SerialNumber>
  annotations:
    Revoked: <Revoked>
    RevocationDate: <RevocationDate>
    RevocationReasonCode: <RevocationReasonCode>
    ExpirationDate: <ExpirationDate>
    InternalState: csasa<InternalState>csasa

# groups related to the privileges
- !group certificates/<SerialNumber>-read
- !group certificates/<SerialNumber>-revoke

# assign the privileges to the groups above
- !permit
  role: !group certificates/<SerialNumber>-read
  resource: !webservice
  privileges:
  - read-certificate-<SerialNumber>
- !permit
  role: !group certificates/<SerialNumber>-revoke
  resource: !webservice
  privileges:
  - revoke-certificate-<SerialNumber>

# assign global level groups the ability to read and revoke these certificates
- !grant
  role: !group certificates/<SerialNumber>-read
  member: !group read-certificates

- !grant
  role: !group certificates/<SerialNumber>-revoke
  member: !group revoke-certificates
`
}

func defaultRevokeCertificatePolicy() string {
	return `- !variable
  id: certificates/<SerialNumber>
  annotations:
    Revoked: <Revoked>
    RevocationDate: <RevocationDate>
    RevocationReasonCode: <RevocationReasonCode>
    InternalState: csasa<InternalState>csasa
`
}

func defaultDeleteTemplatePolicy() string {
	return `
- !delete
  record: !variable templates/<TemplateName>
- !delete
  record: !group templates/<TemplateName>-read
- !delete
  record: !group templates/<TemplateName>-manage
- !delete
  record: !group templates/<TemplateName>-delete
- !delete
  record: !group templates/<TemplateName>-create-certificates
- !delete
  record: !group templates/<TemplateName>-sign-certificates
`
}

func defaultDeleteCertificatePolicy() string {
	return `
- !delete
  record: !variable certificates/<SerialNumber>

- !delete
  record: !group certificates/<SerialNumber>-read

- !delete
  record: !group certificates/<SerialNumber>-revoke
`
}

func defaultCreateSSHTemplatePolicy() string {
	return `
- !variable
  id: ssh-templates/<TemplateName>

# groups related to the privileges
- !group ssh-templates/<TemplateName>-read
- !group ssh-templates/<TemplateName>-manage
- !group ssh-templates/<TemplateName>-delete
- !group ssh-templates/<TemplateName>-create-certificates

# assign the privileges to the groups above
- !permit
  role: !group ssh-templates/<TemplateName>-read
  resource: !webservice
  privileges:
  - read-ssh-template-<TemplateName>

- !permit
  role: !group ssh-templates/<TemplateName>-manage
  resource: !webservice
  privileges:
  - manage-ssh-template-<TemplateName>

- !permit
  role: !group ssh-templates/<TemplateName>-delete
  resource: !webservice
  privileges:
  - delete-ssh-template-<TemplateName>

- !permit
  role: !group ssh-templates/<TemplateName>-create-certificates
  resource: !webservice
  privileges:
  - create-ssh-certificate-from-<TemplateName>


# grant the groups accordingly
- !grant
  role: !group ssh-templates/<TemplateName>-read
  member: !group read-ssh-templates

- !grant
  role: !group ssh-templates/<TemplateName>-manage
  member: !group manage-ssh-templates

- !grant
  role: !group ssh-templates/<TemplateName>-delete
  member: !group delete-ssh-templates

- !grant
  role: !group ssh-templates/<TemplateName>-create-certificates
  member: !group create-ssh-certificates
`
}

func defaultDeleteSSHTemplatePolicy() string {
	return `
- !delete
  record: !variable ssh-templates/<TemplateName>
- !delete
  record: !group ssh-templates/<TemplateName>-read
- !delete
  record: !group ssh-templates/<TemplateName>-manage
- !delete
  record: !group ssh-templates/<TemplateName>-delete
- !delete
  record: !group ssh-templates/<TemplateName>-create-certificates
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
	log.Info("Conjur appliance URL: %s", conjurClient.GetConfig().ApplianceURL)
	log.Info("Conjur account: %s", conjurClient.GetConfig().Account)
	log.Info("Conjur SSL cert path: %s", conjurClient.GetConfig().SSLCertPath)

	role, err := getApplianceRole(conjurClient)
	if err != nil {
		return StorageBackend{}, err
	}
	log.Info("Conjur appliance role: %s", role)

	policyTemplates := NewDefaultTemplates()

	access := NewAccessFromDefaults(conjurClient.GetConfig(), defaultPolicyBranch())

	return NewConjurPki(conjurClient, defaultPolicyBranch(), policyTemplates, access, role), nil
}

// NewTemplates ...
func NewTemplates(newTemplate string, deleteTemplate string, newCertificate string, deleteCertificate string, revokedCertificate string, newSSHTemplate string, deleteSSHTemplate string) PolicyTemplates {
	return PolicyTemplates{
		newTemplate:       newTemplate,
		deleteTemplate:    deleteTemplate,
		newCertificate:    newCertificate,
		deleteCertificate: deleteCertificate,
		revokeCertificate: revokedCertificate,
		newSSHTemplate:    newSSHTemplate,
		deleteSSHTemplate: deleteSSHTemplate,
	}
}

// NewDefaultTemplates calls NewTemplates with all of the default policy templates
func NewDefaultTemplates() PolicyTemplates {
	return NewTemplates(
		defaultCreateTemplatePolicy(),
		defaultDeleteTemplatePolicy(),
		defaultCreateCertificatePolicy(),
		defaultDeleteCertificatePolicy(),
		defaultRevokeCertificatePolicy(),
		defaultCreateSSHTemplatePolicy(),
		defaultDeleteSSHTemplatePolicy(),
	)
}

// NewConjurPki ...
func NewConjurPki(client *conjurapi.Client, policyBranch string, templates PolicyTemplates, access AccessControl, role Role) StorageBackend {
	return StorageBackend{
		client:       client,
		policyBranch: policyBranch,
		templates:    templates,
		Access:       access,
		role:         role,
	}
}
