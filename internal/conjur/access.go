package conjur

import (
	"fmt"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi"
)

// Privileges ...
type Privileges struct {
	Authenticate              string
	Admin                     string
	Audit                     string
	CertificateAdmin          string
	TemplateAdmin             string
	Purge                     string
	CRLPurge                  string
	CertificateSignAny        string
	CertificateSignSpecific   string
	CertificateCreateAny      string
	CertificateCreateSpecific string
	CertificateRevokeAny      string
	CertificateRevokeSpecific string
	TemplateCreateAny         string
	TemplateManageAny         string
	TemplateManageSpecific    string
	TemplateDeleteAny         string
	TemplateDeleteSpecific    string
	TemplateReadAny           string
	TemplateReadSpecific      string
}

// NewDefaultPrivileges ...
func NewDefaultPrivileges() Privileges {
	return Privileges{
		Authenticate:              "use",
		Admin:                     "admin",
		Audit:                     "audit",
		CertificateAdmin:          "certificate/admin",
		TemplateAdmin:             "template/admin",
		Purge:                     "purge",
		CRLPurge:                  "crl/purge",
		CertificateSignAny:        "certificate/sign",
		CertificateSignSpecific:   "certificates/sign/{templateName}",
		CertificateCreateAny:      "certificate/create",
		CertificateCreateSpecific: "certificate/create/{templateName}",
		CertificateRevokeAny:      "certificate/revoke",
		CertificateRevokeSpecific: "certificate/revoke/{serialNumber}",
		TemplateCreateAny:         "template/create",
		TemplateManageAny:         "template/manage",
		TemplateManageSpecific:    "template/manage/{templateName}",
		TemplateDeleteAny:         "template/delete",
		TemplateDeleteSpecific:    "template/delete/{templateName}",
		TemplateReadAny:           "templates",
		TemplateReadSpecific:      "template/{templateName}",
	}
}

func replacePrivilege(privilege string, key string, value string) string {
	return strings.ReplaceAll(privilege, fmt.Sprintf("{%s}", key), value)
}

// Access ...
type Access struct {
	conjur     ConjurPki
	privileges Privileges
}

// NewAccess ...
func NewAccess(conjur ConjurPki, privileges Privileges) Access {
	return Access{
		conjur:     conjur,
		privileges: privileges,
	}
}

// NewAccessFromDefaults ...
func NewAccessFromDefaults(conjur ConjurPki) Access {
	return NewAccess(conjur, NewDefaultPrivileges())
}

// Authenticate ...
func (a Access) Authenticate(accessToken string) error {
	authenticated, err := a.checkPermission(accessToken, a.privileges.Authenticate)
	if err != nil {
		return fmt.Errorf("Failed to authenticate as client. %s", err)
	}
	if !authenticated {
		return fmt.Errorf("You are not authenticated to use this PKI service")
	}
	return nil
}

// ReadTemplates ...
func (a Access) ReadTemplates(accessToken string) error {
	permissions := []string{
		a.privileges.Admin,
		a.privileges.Audit,
		a.privileges.TemplateAdmin,
		a.privileges.TemplateCreateAny,
		a.privileges.TemplateManageAny,
		a.privileges.TemplateReadAny,
	}

	return a.checkPermissions(accessToken, permissions)
}

// ReadTemplate ...
func (a Access) ReadTemplate(accessToken string, templateName string) error {
	err := a.ReadTemplates(accessToken)
	if err == nil {
		return nil
	}

	permissions := []string{
		replacePrivilege(a.privileges.TemplateReadSpecific, "templateName", templateName),
	}

	return a.checkPermissions(accessToken, permissions)
}

// DeleteTemplate ..
func (a Access) DeleteTemplate(accessToken string, templateName string) error {
	permissions := []string{
		a.privileges.Admin,
		a.privileges.TemplateAdmin,
		a.privileges.TemplateCreateAny,
		a.privileges.TemplateDeleteAny,
		replacePrivilege(a.privileges.TemplateDeleteSpecific, "templateName", templateName),
	}

	return a.checkPermissions(accessToken, permissions)
}

// ManageTemplate ...
func (a Access) ManageTemplate(accessToken string, templateName string) error {
	permissions := []string{
		a.privileges.Admin,
		a.privileges.TemplateAdmin,
		a.privileges.TemplateCreateAny,
		a.privileges.TemplateManageAny,
		replacePrivilege(a.privileges.TemplateManageSpecific, "templateName", templateName),
	}

	return a.checkPermissions(accessToken, permissions)
}

// CreateTemplate ...
func (a Access) CreateTemplate(accessToken string) error {
	permissions := []string{
		a.privileges.Admin,
		a.privileges.TemplateAdmin,
		a.privileges.TemplateCreateAny,
	}

	return a.checkPermissions(accessToken, permissions)
}

// Purge ...
func (a Access) Purge(accessToken string) error {
	// Should Template admins or Cert admins also be able to purge?
	permissions := []string{
		a.privileges.Admin,
		a.privileges.Purge,
	}

	return a.checkPermissions(accessToken, permissions)
}

// CRLPurge ...
func (a Access) CRLPurge(accessToken string) error {
	// Should Template admins or Cert admins also be able to purge?
	permissions := []string{
		a.privileges.Admin,
		a.privileges.Purge,
		a.privileges.CRLPurge,
	}

	return a.checkPermissions(accessToken, permissions)
}

// CreateCertificate ...
func (a Access) CreateCertificate(accessToken string, templateName string) error {
	permissions := []string{
		a.privileges.Admin,
		a.privileges.CertificateAdmin,
		a.privileges.CertificateCreateAny,
		replacePrivilege(a.privileges.CertificateCreateSpecific, "templateName", templateName),
	}

	return a.checkPermissions(accessToken, permissions)
}

// RevokeCertificate ...
func (a Access) RevokeCertificate(accessToken string, templateName string) error {
	permissions := []string{
		a.privileges.Admin,
		a.privileges.CertificateAdmin,
		a.privileges.CertificateCreateAny,
		a.privileges.CertificateRevokeAny,
		replacePrivilege(a.privileges.CertificateRevokeSpecific, "templateName", templateName),
	}

	return a.checkPermissions(accessToken, permissions)
}

// SignCertificate ...
func (a Access) SignCertificate(accessToken string, templateName string) error {
	permissions := []string{
		a.privileges.Admin,
		a.privileges.CertificateAdmin,
		a.privileges.CertificateSignAny,
		replacePrivilege(a.privileges.CertificateSignSpecific, "templateName", templateName),
	}

	return a.checkPermissions(accessToken, permissions)
}

func (a Access) checkPermissions(accessToken string, permissions []string) error {
	config := a.conjur.client.GetConfig()
	conjur, err := conjurapi.NewClientFromToken(config, accessToken)
	if err != nil {
		return fmt.Errorf("Failed to init conjur client. %s", err)
	}

	resourceID := fmt.Sprintf("%s:%s:%s", config.Account, "webservice", a.conjur.policyBranch)
	for _, permission := range permissions {
		privilege, _ := conjur.CheckPermission(resourceID, permission)
		if privilege {
			return nil
		}
	}

	return fmt.Errorf("Privileges '%s' were not found on resource '%s'", strings.Join(permissions, ", "), resourceID)
}

func (a Access) checkPermission(accessToken string, permission string) (bool, error) {
	config := a.conjur.client.GetConfig()
	conjur, err := conjurapi.NewClientFromToken(config, accessToken)
	if err != nil {
		return false, fmt.Errorf("Failed to init conjur client. %s", err)
	}

	resourceID := fmt.Sprintf("%s:%s:%s", config.Account, "webservice", a.conjur.policyBranch)
	allowed, err := conjur.CheckPermission(resourceID, a.privileges.Authenticate)
	return allowed, err
}