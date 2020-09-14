package conjur

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/pki"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/pkg/log"
)

// Privileges ...
type Privileges struct {
	Authenticate                 string
	Purge                        string
	CRLPurge                     string
	CertificateSignSpecific      string
	CertificateCreateSpecific    string
	CertificateRevokeSpecific    string
	TemplateCreateAny            string
	TemplateManageSpecific       string
	TemplateDeleteSpecific       string
	TemplateReadSpecific         string
	ListTemplates                string
	GenerateIntermediateCSR      string
	SetIntermediateCertificate   string
	SetCAChain                   string
	SSHTemplateCreateAny         string
	SSHTemplateManageSpecific    string
	SSHTemplateDeleteSpecific    string
	SSHTemplateReadSpecific      string
	ListSSHTemplates             string
	SSHCertificateCreateSpecific string
}

// AccessControl ...
type AccessControl struct {
	privileges   Privileges
	policyBranch string
	conjurConfig conjurapi.Config
	disabled     bool
}

// AccessToken ...
type AccessToken struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// Payload ...
type Payload struct {
	Sub string `json:"sub"`
	Iat int    `json:"iat"`
}

// NewDefaultPrivileges ...
func NewDefaultPrivileges() Privileges {
	return Privileges{
		Authenticate:                 "authenticate",
		Purge:                        "purge",
		CRLPurge:                     "purge-crl",
		CertificateSignSpecific:      "sign-certificate-from-",
		CertificateCreateSpecific:    "create-certificate-from-",
		CertificateRevokeSpecific:    "revoke-certificate-",
		TemplateCreateAny:            "create-templates",
		TemplateManageSpecific:       "manage-template-",
		TemplateDeleteSpecific:       "delete-template-",
		TemplateReadSpecific:         "read-template-",
		ListTemplates:                "list-templates",
		GenerateIntermediateCSR:      "generate-intermediate-csr",
		SetIntermediateCertificate:   "set-intermediate-certificate",
		SetCAChain:                   "set-ca-chain",
		SSHTemplateCreateAny:         "create-ssh-templates",
		SSHTemplateManageSpecific:    "manage-ssh-template-",
		SSHTemplateDeleteSpecific:    "delete-ssh-template-",
		SSHTemplateReadSpecific:      "read-ssh-template-",
		ListSSHTemplates:             "list-ssh-templates",
		SSHCertificateCreateSpecific: "create-ssh-certificate-from-",
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

func replacePrivilege(privilege string, key string, value string) string {
	return strings.ReplaceAll(privilege, fmt.Sprintf("{%s}", key), value)
}

func parseAccessToken(accessToken string) (string, error) {
	accessToken = strings.ReplaceAll(accessToken, "Token token=\"", "")
	accessToken = strings.Trim(accessToken, "\"")

	accessTokenSlice, err := base64.StdEncoding.DecodeString(accessToken)
	return string(accessTokenSlice), err
}

func getJWT(accessToken string) AccessToken {
	var accessTokenJSON AccessToken
	decoder := json.NewDecoder(strings.NewReader(accessToken))
	decoder.Decode(&accessTokenJSON)
	return accessTokenJSON
}

func getLogin(accessToken string) string {
	JWT := getJWT(accessToken)
	decoded, err := base64.StdEncoding.DecodeString(JWT.Payload)
	if err != nil {
		return ""
	}

	var payload Payload
	decoder := json.NewDecoder(strings.NewReader(string(decoded)))
	decoder.Decode(&payload)
	return payload.Sub
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
	return a.checkPermission(accessToken, a.privileges.ListSSHTemplates)
}

// ReadSSHTemplate ----
func (a AccessControl) ReadSSHTemplate(accessToken string, templateName string) error {
	return a.checkPermission(accessToken, a.privileges.SSHTemplateReadSpecific+templateName)
}

// DeleteSSHTemplate ----
func (a AccessControl) DeleteSSHTemplate(accessToken string, templateName string) error {
	return a.checkPermission(accessToken, a.privileges.SSHTemplateDeleteSpecific+templateName)
}

// ManageSSHTemplate ---
func (a AccessControl) ManageSSHTemplate(accessToken string, templateName string) error {
	return a.checkPermission(accessToken, a.privileges.SSHTemplateManageSpecific+templateName)
}

// CreateSSHTemplate ----
func (a AccessControl) CreateSSHTemplate(accessToken string) error {
	return a.checkPermission(accessToken, a.privileges.SSHTemplateCreateAny)
}

// CreateSSHCertificate ----
func (a AccessControl) CreateSSHCertificate(accessToken string, templateName string) error {
	return a.checkPermission(accessToken, a.privileges.SSHCertificateCreateSpecific+templateName)
}

func (a AccessControl) checkPermission(accessToken string, permission string) error {
	if a.disabled {
		return nil
	}

	accessToken, err := parseAccessToken(accessToken)
	if err != nil {
		return log.Error("Failed to parse access token. %s", err)
	}
	login := getLogin(accessToken)

	config := a.conjurConfig
	conjur, err := conjurapi.NewClientFromToken(config, accessToken)
	if err != nil {
		return log.Error("Failed to init conjur client. %s", err)
	}

	resourceID := fmt.Sprintf("%s:%s:%s", config.Account, "webservice", a.policyBranch)
	allowed, err := conjur.CheckPermission(resourceID, permission)

	if err != nil {
		return log.Error("Failed to check for permission '%s'. %s", permission, err)
	}

	if allowed {
		log.Debug("Identity '%s' has privilege to '%s'", login, permission)
		return nil
	}

	return log.Error("Identity '%s' does not have privilege to '%s'", login, permission)
}

// ListSSHTemplates ----
func (a AccessControl) ListSSHTemplates(accessToken string) error { return nil }

// ReadSSHTemplate ----
func (a AccessControl) ReadSSHTemplate(accessToken string, templateName string) error { return nil }

// DeleteSSHTemplate ----
func (a AccessControl) DeleteSSHTemplate(accessToken string, templateName string) error { return nil }

// ManageSSHTemplate ---
func (a AccessControl) ManageSSHTemplate(accessToken string, templateName string) error { return nil }

// CreateSSHTemplate ----
func (a AccessControl) CreateSSHTemplate(accessToken string) error { return nil }

// CreateSSHCertificate ----
func (a AccessControl) CreateSSHCertificate(accessToken string, templateName string) error {
	return nil
}
