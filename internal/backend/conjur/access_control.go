package conjur

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/pki"
)

// Privileges ...
type Privileges struct {
	Authenticate               string
	Purge                      string
	CRLPurge                   string
	CertificateSignSpecific    string
	CertificateCreateSpecific  string
	CertificateRevokeSpecific  string
	TemplateCreateAny          string
	TemplateManageSpecific     string
	TemplateDeleteSpecific     string
	TemplateReadSpecific       string
	ListTemplates              string
	GenerateIntermediateCSR    string
	SetIntermediateCertificate string
	SetCAChain                 string
}

// AccessControl ...
type AccessControl struct {
	privileges   Privileges
	policyBranch string
	conjurConfig conjurapi.Config
	disabled     bool
}

// NewDefaultPrivileges ...
func NewDefaultPrivileges() Privileges {
	return Privileges{
		Authenticate:               "authenticate",
		Purge:                      "purge",
		CRLPurge:                   "purge-crl",
		CertificateSignSpecific:    "sign-certificate-from-",
		CertificateCreateSpecific:  "create-certificate-from-",
		CertificateRevokeSpecific:  "revoke-certificate-",
		TemplateCreateAny:          "create-templates",
		TemplateManageSpecific:     "manage-template-",
		TemplateDeleteSpecific:     "delete-template-",
		TemplateReadSpecific:       "read-template-",
		ListTemplates:              "list-templates",
		GenerateIntermediateCSR:    "generate-intermediate-csr",
		SetIntermediateCertificate: "set-intermediate-certificate",
		SetCAChain:                 "set-ca-chain",
	}
}

// NewAccess ...
func NewAccess(conjurConfig conjurapi.Config, policyBranch string, privileges Privileges, disabled bool) AccessControl {
	return AccessControl{
		conjurConfig: conjurConfig,
		policyBranch: policyBranch,
		privileges:   privileges,
		disabled:     disabled,
	}
}

// NewAccessFromDefaults ...
func NewAccessFromDefaults(conjurConfig conjurapi.Config, policyBranch string) AccessControl {
	return NewAccess(conjurConfig, policyBranch, NewDefaultPrivileges(), false)
}

// NewAccessFromDefaultsDisabled ...
func NewAccessFromDefaultsDisabled(conjurConfig conjurapi.Config, policyBranch string) AccessControl {
	return NewAccess(conjurConfig, policyBranch, NewDefaultPrivileges(), true)
}

func parseAccessToken(accessToken string) (string, error) {
	accessToken = strings.ReplaceAll(accessToken, "Token token=\"", "")
	accessToken = strings.Trim(accessToken, "\"")

	accessTokenSlice, err := base64.StdEncoding.DecodeString(accessToken)
	return string(accessTokenSlice), err
}

// Authenticate If the client has ability to authenticate to the PKI service
func (a AccessControl) Authenticate(accessToken string) error {
	return a.checkPermission(accessToken, a.privileges.Authenticate)
}

// ListTemplates ...
func (a AccessControl) ListTemplates(accessToken string) error {
	return a.checkPermission(accessToken, a.privileges.ListTemplates)
}

// ReadTemplate ...
func (a AccessControl) ReadTemplate(accessToken string, templateName string) error {
	return a.checkPermission(accessToken, a.privileges.TemplateReadSpecific+templateName)
}

// DeleteTemplate ..
func (a AccessControl) DeleteTemplate(accessToken string, templateName string) error {
	return a.checkPermission(accessToken, a.privileges.TemplateDeleteSpecific+templateName)
}

// ManageTemplate ...
func (a AccessControl) ManageTemplate(accessToken string, templateName string) error {
	return a.checkPermission(accessToken, a.privileges.TemplateManageSpecific+templateName)
}

// CreateTemplate creating a template is not granular, you either have the ability to create templates or not
func (a AccessControl) CreateTemplate(accessToken string) error {
	return a.checkPermission(accessToken, a.privileges.TemplateCreateAny)
}

// Purge ...
func (a AccessControl) Purge(accessToken string) error {
	return a.checkPermission(accessToken, a.privileges.Purge)
}

// CRLPurge ...
func (a AccessControl) CRLPurge(accessToken string) error {
	return a.checkPermission(accessToken, a.privileges.CRLPurge)
}

// CreateCertificate ...
func (a AccessControl) CreateCertificate(accessToken string, templateName string) error {
	return a.checkPermission(accessToken, a.privileges.CertificateCreateSpecific+templateName)
}

// RevokeCertificate ...
func (a AccessControl) RevokeCertificate(accessToken string, serialNumber string) error {
	serialNumberInt, _ := pki.ConvertSerialOctetStringToInt(serialNumber)
	return a.checkPermission(accessToken, a.privileges.CertificateRevokeSpecific+serialNumberInt.String())
}

// SignCertificate ...
func (a AccessControl) SignCertificate(accessToken string, templateName string) error {
	return a.checkPermission(accessToken, a.privileges.CertificateSignSpecific+templateName)
}

// GenerateIntermediateCSR ...
func (a AccessControl) GenerateIntermediateCSR(accessToken string) error {
	return a.checkPermission(accessToken, a.privileges.GenerateIntermediateCSR)
}

// SetIntermediateCertificate ...
func (a AccessControl) SetIntermediateCertificate(accessToken string) error {
	return a.checkPermission(accessToken, a.privileges.SetIntermediateCertificate)
}

// SetCAChain ...
func (a AccessControl) SetCAChain(accessToken string) error {
	return a.checkPermission(accessToken, a.privileges.SetCAChain)
}

func (a AccessControl) checkPermission(accessToken string, permission string) error {
	if a.disabled {
		return nil
	}

	accessToken, err := parseAccessToken(accessToken)
	if err != nil {
		return fmt.Errorf("Failed to parse access token. %s", err)
	}

	config := a.conjurConfig
	conjur, err := conjurapi.NewClientFromToken(config, accessToken)
	if err != nil {
		return fmt.Errorf("Failed to init conjur client. %s", err)
	}

	resourceID := fmt.Sprintf("%s:%s:%s", config.Account, "webservice", a.policyBranch)
	allowed, err := conjur.CheckPermission(resourceID, permission)

	if err != nil {
		return fmt.Errorf("Could not check the permissions. %s", err)
	}

	if allowed {
		return nil
	}
	return fmt.Errorf("You do not have the privilege '%s'", permission)
}
