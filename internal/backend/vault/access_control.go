package vault

import (
	"errors"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/hashicorp/vault/api"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/pki"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/pkg/log"
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
	privileges Privileges
	disabled   bool
}

// NewDefaultPrivileges ...
func NewDefaultPrivileges() Privileges {
	return Privileges{
		Authenticate:               "authenticate",
		Purge:                      "purge",
		CRLPurge:                   "purge-crl",
		GenerateIntermediateCSR:    "generate-intermediate-csr",
		SetIntermediateCertificate: "set-intermediate-certificate",
		SetCAChain:                 "set-ca-chain",
		CertificateSignSpecific:    "templates/sign-cert/",
		CertificateCreateSpecific:  "templates/create-cert/",
		TemplateCreateAny:          "templates/create",
		TemplateManageSpecific:     "templates/manage/",
		TemplateDeleteSpecific:     "templates/delete/",
		TemplateReadSpecific:       "templates/read/",
		ListTemplates:              "templates/list",
		CertificateRevokeSpecific:  "certificates/revoke/",
	}
}

// NewAccess ...
func NewAccess(privileges Privileges, disabled bool) AccessControl {
	return AccessControl{
		privileges: privileges,
		disabled:   disabled,
	}
}

// NewAccessFromDefaults ...
func NewAccessFromDefaults() AccessControl {
	return NewAccess(NewDefaultPrivileges(), false)
}

// NewAccessFromDefaultsDisabled ...
func NewAccessFromDefaultsDisabled(conjurConfig conjurapi.Config, policyBranch string) AccessControl {
	return NewAccess(NewDefaultPrivileges(), true)
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

// ListSSHTemplates ----
func (a AccessControl) ListSSHTemplates(accessToken string) error {
	return errors.New("Not implemented")
}

// ReadSSHTemplate ----
func (a AccessControl) ReadSSHTemplate(accessToken string, templateName string) error {
	return errors.New("Not implemented")
}

// DeleteSSHTemplate ----
func (a AccessControl) DeleteSSHTemplate(accessToken string, templateName string) error {
	return errors.New("Not implemented")
}

// ManageSSHTemplate ---
func (a AccessControl) ManageSSHTemplate(accessToken string, templateName string) error {
	return errors.New("Not implemented")
}

// CreateSSHTemplate ----
func (a AccessControl) CreateSSHTemplate(accessToken string) error {
	return errors.New("Not implemented")
}

// CreateSSHCertificate ----
func (a AccessControl) CreateSSHCertificate(accessToken string, templateName string) error {
	return errors.New("Not implemented")
}

func (a AccessControl) checkPermission(accessToken string, permission string) error {
	if a.disabled {
		return nil
	}

	config := api.DefaultConfig()
	client, err := api.NewClient(config)
	if err != nil {
		return log.Error("Failed to init vault client. %s", err)
	}
	client.SetToken(accessToken)

	permission = "pki-service/" + permission
	capabilities, err := client.Sys().CapabilitiesSelf(permission)
	if err != nil {
		return log.Error("Failed to check for permission '%s'. %s", permission, err)
	}
	for _, c := range capabilities {
		if c == "read" {
			log.Debug("Identity has privilege to read '%s'", permission)
			return nil
		}
	}

	return log.Error("Identity does not have privilege to '%s'", permission)
}
