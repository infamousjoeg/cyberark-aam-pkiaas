package ssh

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/httperror"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/pki"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
	"golang.org/x/crypto/ssh"
)

// CreateSSHTemplate Validates the HTTP request data and creates a new SSH template based on the critera defined
// in `template` and writes it tothe storage backend
func CreateSSHTemplate(template types.SSHTemplate, storage backend.Storage) httperror.HTTPError {
	err := ValidateRequestHosts(template.AllowedHosts)
	if err != nil {
		return httperror.SSHInvalidHost(err.Error())
	}

	err = ValidateRequestPrincipals(template.AllowedPrincipals)
	if err != nil {
		return httperror.SSHInvalidPrincipal(err.Error())
	}
	if strings.ToUpper(template.CertType) != "USER" && strings.ToUpper(template.CertType) != "HOST" {
		return httperror.SSHInvalidCertType()
	}
	err = storage.CreateSSHTemplate(template)
	if err != nil {
		return httperror.StorageWriteFail(err.Error())
	}
	return httperror.HTTPError{}
}

// GetSSHTemplate Retrieves the SSH template defined by `templateName` from the storage backend and returns it
// to the HTTP controller function
func GetSSHTemplate(templateName string, storage backend.Storage) (types.SSHTemplate, httperror.HTTPError) {
	template, err := storage.GetSSHTemplate(templateName)

	if err != nil {
		httpErr := httperror.StorageReadFail(err.Error())
		return types.SSHTemplate{}, httpErr
	}

	return template, httperror.HTTPError{}
}

// DeleteSSHTemplate Deletes the SSH template requested by `templateName` from the storage backend
func DeleteSSHTemplate(templateName string, storage backend.Storage) httperror.HTTPError {
	err := storage.DeleteSSHTemplate(templateName)
	if err != nil {
		return httperror.StorageDeleteFail(err.Error())
	}
	return httperror.HTTPError{}
}

// ListSSHTemplates Collects a list of all available SSH templates from the storage backend
func ListSSHTemplates(storage backend.Storage) (types.TemplateListResponse, httperror.HTTPError) {
	templates, err := storage.ListSSHTemplates()
	if err != nil {
		return types.TemplateListResponse{}, httperror.StorageReadFail(err.Error())
	}
	respTemplates := types.TemplateListResponse{
		Templates: templates,
	}

	return respTemplates, httperror.HTTPError{}
}

// CreateSSHCertificate Accepts a request with an authorized key public key, signs it with the intermediate CA key
// and returns the SSH certificate to the requestor
func CreateSSHCertificate(certReq types.SSHSignRequest, storage backend.Storage) (types.SSHCertificate, httperror.HTTPError) {
	signingKey, err := storage.GetSigningKey()
	if err != nil {
		return types.SSHCertificate{}, httperror.SigningKeyReadFail(err.Error())
	}
	template, err := storage.GetSSHTemplate(certReq.TemplateName)
	if err != nil {
		return types.SSHCertificate{}, httperror.StorageReadFail(err.Error())
	}

	err = ValidateAllowedPrincipals(template.AllowedPrincipals, certReq.ValidPrincipals)
	if err != nil {
		return types.SSHCertificate{}, httperror.SSHForbiddenPrincipal(err.Error())
	}

	err = ValidateAllowedHosts(template.AllowedHosts, certReq.Domains)
	if err != nil {
		return types.SSHCertificate{}, httperror.SSHForbiddenHost(err.Error())
	}

	if ValidateAllowedCriticalOptions(template.PermittedCriticalOptions, certReq.CriticalOptions) != nil {
		return types.SSHCertificate{}, httperror.SSHForbiddenCriticalOption(err.Error())
	}

	if ValidateAllowedExtensions(template.PermittedExtensions, certReq.Extensions) != nil {
		return types.SSHCertificate{}, httperror.SSHForbiddenExtension(err.Error())
	}

	var certType uint32
	if strings.ToUpper(template.CertType) == "HOST" {
		certType = ssh.HostCert
	}
	if strings.ToUpper(template.CertType) == "USER" {
		certType = ssh.UserCert
	}

	criticalOptions := make(map[string]string)
	for _, option := range certReq.CriticalOptions {
		criticalOptions[option.Option] = option.Value
	}
	if len(certReq.Domains) > 0 {
		criticalOptions["source-address"] = strings.Join(certReq.Domains, ",")
	}

	extensions := make(map[string]string)
	for _, extension := range certReq.Extensions {
		extensions[extension] = ""
	}

	pubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certReq.PublicKey))
	if err != nil {
		return types.SSHCertificate{}, httperror.ParsePublicKeyError(err.Error())
	}

	decodedKey, err := base64.StdEncoding.DecodeString(signingKey)
	if err != nil {
		return types.SSHCertificate{}, httperror.DecodeSigningKeyError(err.Error())
	}

	signer, err := ssh.ParsePrivateKey(decodedKey)
	if err != nil {
		return types.SSHCertificate{}, httperror.ParseSigningKeyError(err.Error())
	}

	serialNumber, err := pki.GenerateSerialNumber(storage)
	if err != nil {
		return types.SSHCertificate{}, httperror.GenerateSerialFail(err.Error())
	}

	var ttl uint64
	if certReq.TTL > template.MaxTTL {
		ttl = template.MaxTTL
	} else {
		ttl = certReq.TTL
	}

	// Retrieve the intermediate CA certificate from backend and go through the necessary steps
	// to convert it from a PEM-string to a usable x509.Certificate object
	strCert, err := storage.GetSigningCert()
	if err != nil {
		return types.SSHCertificate{}, httperror.StorageReadFail(err.Error())
	}

	derCACert, err := base64.StdEncoding.DecodeString(strCert)
	if err != nil {
		return types.SSHCertificate{}, httperror.DecodeCertError(err.Error())
	}
	caCert, err := x509.ParseCertificate(derCACert)
	if err != nil {
		return types.SSHCertificate{}, httperror.ParseCertificateError(err.Error())
	}

	// Validate that requested certificate is within validity period of CA certificate
	if caCert.NotAfter.Sub(time.Now().Add(time.Minute*time.Duration(ttl)).UTC()) < 0 {
		return types.SSHCertificate{}, httperror.InvalidValidityPeriod()
	}

	certificate := &ssh.Certificate{
		Nonce:           []byte{},
		Serial:          serialNumber.Uint64(),
		Key:             pubkey,
		CertType:        certType,
		ValidPrincipals: certReq.ValidPrincipals,
		ValidBefore:     uint64(time.Now().Unix()) + ttl,
		SignatureKey:    signer.PublicKey(),
	}
	if certType == ssh.UserCert {
		certificate.Permissions.CriticalOptions = criticalOptions
		certificate.Permissions.Extensions = extensions
	}
	err = certificate.SignCert(rand.Reader, signer)
	if err != nil {
		fmt.Println("SignCert: " + err.Error())
		return types.SSHCertificate{}, httperror.CreateCertificateFail(err.Error())
	}
	return types.SSHCertificate{Certificate: string(ssh.MarshalAuthorizedKey(certificate))}, httperror.HTTPError{}
}
