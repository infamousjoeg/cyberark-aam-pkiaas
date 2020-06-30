package pki_test

import (
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend/dummy"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/pki"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

func errorContains(err error, sub string) bool {
	if strings.Contains(err.Error(), sub) {
		return true
	}
	return false
}

func TestValidateContentType(t *testing.T) {
	header := make(map[string][]string)
	header["Content-Type"] = []string{"application/json"}
	valid := pki.ValidateContentType(header, "application/json")
	if !valid {
		t.Errorf("Failed to validate Content-Type of application/json")
	}
}

func TestInvalidContentType(t *testing.T) {
	header := make(map[string][]string)
	header["Content-Type"] = []string{"not/application/json"}
	valid := pki.ValidateContentType(header, "application/json")
	if valid {
		t.Errorf("Validated successfully however Content-Type is invalid")
	}
}

func TestGenerateKeysRsa2048(t *testing.T) {
	algo := "RsA"
	keySize := "2048"
	privateKey, publicKey, err := pki.GenerateKeys(algo, keySize)
	if privateKey == "" {
		t.Errorf("Failed to generate private key for '%s' with key size of '%s'. %s", algo, keySize, err)
	}
	if publicKey == "" {
		t.Errorf("Failed to generate public key for '%s' with key size of '%s'. %s ", algo, keySize, err)
	}
	if err != nil {
		t.Errorf("Failed to generate public & private key for '%s' with key size of '%s'. %s", algo, keySize, err)
	}
}

func TestGenerateKeysRsaKeySizeNonInteger(t *testing.T) {
	algo := "rsa"
	keySize := "notAnInteger"
	_, _, err := pki.GenerateKeys(algo, keySize)
	if err == nil {
		t.Errorf("Generate public & private key successfully even though keySize is invalid.  %s", err)
	}
	if !errorContains(err, "The key size for RSA keys is required to be an integer greater than 2048 bits") {
		t.Errorf("Invalid error returned when using invalid keyAlgo. %s", err)
	}
}

func TestGenerateKeysRsaLowKeyBits(t *testing.T) {
	algo := "rsa"
	keySize := "1024"
	_, _, err := pki.GenerateKeys(algo, keySize)
	if err == nil {
		t.Errorf("Generate public & private key successfully even though keySize is invalid.  %s", err)
	}
	if !errorContains(err, "The minimum supported size for RSA keys is 2048 bits") {
		t.Errorf("Invalid error returned when using invalid keyAlgo. %s", err)
	}
}

func TestGenerateKeysRsaHighKeyBits(t *testing.T) {
	algo := "rsa"
	keySize := "10000"
	_, _, err := pki.GenerateKeys(algo, keySize)
	if err == nil {
		t.Errorf("Generate public & private key successfully even though keySize is invalid.  %s", err)
	}
	if !errorContains(err, "The maximum supported size for RSA keys is 8192 bits") {
		t.Errorf("Invalid error returned when using invalid keyAlgo. %s", err)
	}
}

func TestGenerateKeysECDSAp224(t *testing.T) {
	algo := "ECDSA"
	keySize := "p224"
	privateKey, publicKey, err := pki.GenerateKeys(algo, keySize)
	if privateKey == "" {
		t.Errorf("Failed to generate private key for '%s' with key size of '%s'. %s", algo, keySize, err)
	}
	if publicKey == "" {
		t.Errorf("Failed to generate public key for '%s' with key size of '%s'. %s ", algo, keySize, err)
	}
	if err != nil {
		t.Errorf("Failed to generate public & private key for '%s' with key size of '%s'. %s", algo, keySize, err)
	}
}

func TestGenerateKeysECDSAp256(t *testing.T) {
	algo := "ECDSA"
	keySize := "p256"
	privateKey, publicKey, err := pki.GenerateKeys(algo, keySize)
	if privateKey == "" {
		t.Errorf("Failed to generate private key for '%s' with key size of '%s'. %s", algo, keySize, err)
	}
	if publicKey == "" {
		t.Errorf("Failed to generate public key for '%s' with key size of '%s'. %s ", algo, keySize, err)
	}
	if err != nil {
		t.Errorf("Failed to generate public & private key for '%s' with key size of '%s'. %s", algo, keySize, err)
	}
}

func TestGenerateKeysECDSAp384(t *testing.T) {
	algo := "ECDSA"
	keySize := "p224"
	privateKey, publicKey, err := pki.GenerateKeys(algo, keySize)
	if privateKey == "" {
		t.Errorf("Failed to generate private key for '%s' with key size of '%s'. %s", algo, keySize, err)
	}
	if publicKey == "" {
		t.Errorf("Failed to generate public key for '%s' with key size of '%s'. %s ", algo, keySize, err)
	}
	if err != nil {
		t.Errorf("Failed to generate public & private key for '%s' with key size of '%s'. %s", algo, keySize, err)
	}
}

func TestGenerateKeysECDSAp521(t *testing.T) {
	algo := "ECDSA"
	keySize := "p224"
	privateKey, publicKey, err := pki.GenerateKeys(algo, keySize)
	if privateKey == "" {
		t.Errorf("Failed to generate private key for '%s' with key size of '%s'. %s", algo, keySize, err)
	}
	if publicKey == "" {
		t.Errorf("Failed to generate public key for '%s' with key size of '%s'. %s ", algo, keySize, err)
	}
	if err != nil {
		t.Errorf("Failed to generate public & private key for '%s' with key size of '%s'. %s", algo, keySize, err)
	}
}

func TestGenerateKeysECDSAKInvalidKeySize(t *testing.T) {
	algo := "ECDSA"
	keySize := "notReal"
	_, _, err := pki.GenerateKeys(algo, keySize)
	if !errorContains(err, "The valid key sizes for ECDSA keys are: p224, p256, p384, or p521") {
		t.Errorf("Key should not have been generated. %s", err)
	}
}

func TestGenerateKeysED25519(t *testing.T) {
	algo := "ED25519"
	keySize := ""
	privateKey, publicKey, err := pki.GenerateKeys(algo, keySize)
	if privateKey == "" {
		t.Errorf("Failed to generate private key for '%s' with key size of '%s'. %s", algo, keySize, err)
	}
	if publicKey == "" {
		t.Errorf("Failed to generate public key for '%s' with key size of '%s'. %s ", algo, keySize, err)
	}
	if err != nil {
		t.Errorf("Failed to generate public & private key for '%s' with key size of '%s'. %s", algo, keySize, err)
	}
}

func TestGenerateKeysInvalidAlgo(t *testing.T) {
	algo := "invalidAlgo"
	keySize := ""
	_, _, err := pki.GenerateKeys(algo, keySize)
	if !errorContains(err, "The provided key algorithm is not valid") {
		t.Errorf("Invalid error message. %s", err)
	}
}

type MockGenerateSerialNumber struct {
	dummy.Dummy
}

func (m MockGenerateSerialNumber) GetCertificate(serialNumber *big.Int) (string, error) {
	return "", fmt.Errorf("Get Certificate does not exists")
}

func TestGenerateSerialNumber(t *testing.T) {
	storage := MockGenerateSerialNumber{}
	serialNumber, err := pki.GenerateSerialNumber(storage)
	if err != nil {
		t.Errorf("Error occured while generating serial number. %s , %s", serialNumber, err)
	}
}

type MockGenerateSerialNumbersExist struct {
	dummy.Dummy
}

func (m MockGenerateSerialNumbersExist) GetCertificate(serialNumber *big.Int) (string, error) {
	return "", nil
}

func TestGenerateSerialNumberNumbersExist(t *testing.T) {
	storage := MockGenerateSerialNumbersExist{}
	serialNumber, err := pki.GenerateSerialNumber(storage)
	if err != nil {
		t.Errorf("Error occured while generating serial number. %s , %s", serialNumber, err)
	}
}

func TestProcessKeyUsages(t *testing.T) {
	keyUsages := []string{"digitalSignature"}
	x509KeyUsage, err := pki.ProcessKeyUsages(keyUsages)
	if err != nil {
		t.Errorf("Error occured during a valid keyUsage. %s", err)
	}
	if x509KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("The keyUsage provided is incorrect. %v", x509KeyUsage)
	}
}

func TestMultipleProcessKeyUsages(t *testing.T) {
	keyUsages := []string{
		"digitalSignature",
		"keyEncipherment",
		"dataEncipherment",
		"contentCommitment",
		"keyAgreement",
		"certSign",
		"crlSign",
		"encipherOnly",
		"decipherOnly",
	}
	x509KeyUsage, err := pki.ProcessKeyUsages(keyUsages)
	if err != nil {
		t.Errorf("Error occured during a valid keyUsage. %s", err)
	}
	if x509KeyUsage != 511 {
		t.Errorf("The keyUsage provided is incorrect. %v", x509KeyUsage)
	}
}

func TestInvalidProcessKeyUsages(t *testing.T) {
	keyUsages := []string{"notRealKeyUsage"}
	_, err := pki.ProcessKeyUsages(keyUsages)
	if err == nil {
		t.Errorf("No error occured during an invalid keyUsage")
	}
}

func TestProcessExtKeyUsages(t *testing.T) {
	extKeyUsages := []string{"any"}
	x509ExtKeyUsages, err := pki.ProcessExtKeyUsages(extKeyUsages)
	if err != nil {
		t.Errorf("Error occured during a valid extKeyUsage. %s", err)
	}

	if x509ExtKeyUsages[0] != x509.ExtKeyUsageAny {
		t.Errorf("Ext key usage is invalid")
	}
}

func TestInvalidProcessExtKeyUsages(t *testing.T) {
	extKeyUsages := []string{"invalidUsage"}
	_, err := pki.ProcessExtKeyUsages(extKeyUsages)
	if err == nil {
		t.Errorf("Error DID NOT occur during an invalid extKeyUsage")
	}
}

func TestAllProcessExtKeyUsages(t *testing.T) {
	extKeyUsages := []string{
		"any",
		"serverAuth",
		"clientAuth",
		"codeSigning",
		"emailProtection",
		"timeStamping",
		"OCSPSigning",
		"ipsecEndSystem",
		"ipsecTunnel",
		"ipsecUser",
		"msSGC",
		"nsSGC",
		"msCodeCom",
		"msCodeKernel",
	}

	x509ExtKeyUsages, err := pki.ProcessExtKeyUsages(extKeyUsages)
	if err != nil {
		t.Errorf("Error occured during a valid extKeyUsage. %s", err)
	}

	if len(x509ExtKeyUsages) != len(extKeyUsages) {
		t.Errorf("Ext key usage is invalid")
	}
}

func TestSetCertSubject(t *testing.T) {
	commonName := "some.common.name.local"
	subFields := types.SubjectFields{}

	subjectName, err := pki.SetCertSubject(subFields, commonName)
	if err != nil {
		t.Errorf("Failed to Set the certificate subject. %s", err)
	}

	if subjectName.CommonName != commonName {
		t.Errorf("Common name '%s' should be the expected common name of '%s", subjectName.CommonName, commonName)
	}
}

func TestAllSetCertSubject(t *testing.T) {
	commonName := "some.common.name.local"
	subFields := types.SubjectFields{
		Organization: "testing",
		OrgUnit:      "pki",
		Country:      "US",
		Locality:     "Boston",
		Province:     "NoIdea",
		Address:      "32 my street",
		PostalCode:   "01590",
	}

	subjectName, err := pki.SetCertSubject(subFields, commonName)
	if err != nil {
		t.Errorf("Failed to Set the certificate subject. %s", err)
	}

	if subjectName.CommonName != commonName {
		t.Errorf("Common name '%s' should be the expected common name of '%s", subjectName.CommonName, commonName)
	}

	if subjectName.Organization[0] != subFields.Organization {
		t.Errorf("Organization was not set correctly")
	}
}

func TestInvalidSetCertSubject(t *testing.T) {
	commonName := ""
	subFields := types.SubjectFields{}

	_, err := pki.SetCertSubject(subFields, commonName)
	if err == nil {
		t.Errorf("Certificate subject SHOULD NOT be created successfully")
	}
}

func TestPrepareCertificateParameters(t *testing.T) {
	//(templateName string, reqTTL int64, backend backend.Storage)
	templateName := "TestTemplate"
	var reqTTL int64 = 1440
	backend := dummy.Dummy{}
	// template, serialNumber, ttl, sigAlgo, caCert, signingKey, err := pki.PrepareCertificateParameters(templateName, reqTTL, backend)
	_, _, ttl, _, _, _, err := pki.PrepareCertificateParameters(templateName, reqTTL, backend)
	if ttl != reqTTL {
		t.Errorf("Time to live was set incorrectly")
	}

	if err != nil {
		t.Errorf("Failed to prepare the certificte parameters. %s", err)
	}
}

func TestInvalidTemplateNamePrepareCertificateParameters(t *testing.T) {
	//(templateName string, reqTTL int64, backend backend.Storage)
	templateName := "invalidTemplateName"
	var reqTTL int64 = 1440
	backend := dummy.Dummy{}
	// template, serialNumber, ttl, sigAlgo, caCert, signingKey, err := pki.PrepareCertificateParameters(templateName, reqTTL, backend)
	_, _, _, _, _, _, err := pki.PrepareCertificateParameters(templateName, reqTTL, backend)

	if err == nil {
		t.Errorf("Error should have been returned when providing invalid template name")
	}

	if err.Error() != fmt.Sprintf("Error retrieving template from backend: Unable to locate template with template name %s", templateName) {
		t.Errorf("Error returned is invalid. %s", err)
	}
}

func TestProcessSubjectAltNames(t *testing.T) {
	altNames := []string{"IP:192.168.1.10"}
	dnsNames, emailAddresses, ipAddresses, URIs, err := pki.ProcessSubjectAltNames(altNames)
	if len(dnsNames) != 0 {
		t.Errorf("Dns name should be empty")
	}
	if len(emailAddresses) != 0 {
		t.Errorf("email addresses should be empty")
	}
	if len(URIs) != 0 {
		t.Errorf("URIs should be empty")
	}
	if len(ipAddresses) != 1 {
		t.Errorf("Only 1 ip address should be returned")
	}
	if err != nil {
		t.Errorf("Error should not be returned when successful process of sub alt name")
	}
}

func TestAllProcessSubjectAltNames(t *testing.T) {
	altNames := []string{
		"IP:192.168.1.10",
		"DNS:Something.local",
		"email:testing@example.org",
		"URI:https://foo.com",
	}

	dnsNames, emailAddresses, ipAddresses, URIs, err := pki.ProcessSubjectAltNames(altNames)
	if len(dnsNames) != 1 {
		t.Errorf("Only 1 DNS name should be returned")
	}
	if len(emailAddresses) != 1 {
		t.Errorf("Only 1 email addresses should be returned")
	}
	if len(URIs) != 1 {
		t.Errorf("Only 1 URIs should be returned")
	}
	if len(ipAddresses) != 1 {
		t.Errorf("Only 1 ip address should be returned")
	}
	if err != nil {
		t.Errorf("Error should not be returned when successful process of sub alt name. %s", err)
	}
}

func TestValidateCommonName(t *testing.T) {
	commonName := "validCommonName.local"
	template, _ := dummy.Dummy{}.GetTemplate("TestTemplate")
	err := pki.ValidateCommonName(commonName, template)
	if err != nil {
		t.Errorf("Common name should be valid. %s", err)
	}
}

func TestInvalidCommonNameValidateCommonName(t *testing.T) {
	commonName := "notValid.local/notValid"
	template, _ := dummy.Dummy{}.GetTemplate("TestTemplate")
	template.ValidateCNHostname = true
	err := pki.ValidateCommonName(commonName, template)
	if err.Error() != "Common Name is not a valid hostname; valid hostname is required by template" {
		t.Errorf("Invalid error message. %s", err)
	}
}

func TestAllValidateCommonName(t *testing.T) {
	commonName := "localhost"
	template, _ := dummy.Dummy{}.GetTemplate("TestTemplate")
	template.ValidateCNHostname = true
	template.PermitLocalhostCN = true
	err := pki.ValidateCommonName(commonName, template)
	if err != nil {
		t.Errorf("Common name should be valid. %s", err)
	}
}

func TestInvalidPermitLocalHostCNValidateCommonName(t *testing.T) {
	commonName := "localhost"
	template, _ := dummy.Dummy{}.GetTemplate("TestTemplate")
	template.PermitLocalhostCN = false
	err := pki.ValidateCommonName(commonName, template)
	if err.Error() != "The requested template does not permit localhost as a common name" {
		t.Errorf("Invalid Error message. %s", err)
	}
}

func TestPermitWildcardCNValidateCommonName(t *testing.T) {
	commonName := "*.example.org"
	template, _ := dummy.Dummy{}.GetTemplate("TestTemplate")
	template.PermitWildcardCN = true
	err := pki.ValidateCommonName(commonName, template)
	if err != nil {
		t.Errorf("Common name should be valid. %s", err)
	}
}

func TestPermitInvalidWildcardCNValidateCommonName(t *testing.T) {
	commonName := "*.example.org"
	template, _ := dummy.Dummy{}.GetTemplate("TestTemplate")
	template.PermitWildcardCN = false
	err := pki.ValidateCommonName(commonName, template)
	if err == nil {
		t.Errorf("Error should have occured since WildcardDN is NOT permitted")
	}
	if err.Error() != "The requested template does not permit wildcards" {
		t.Errorf("Incorrect error message. %s", err)
	}
}

func TestInvalidAllowedCNDomainsValidateCommonName(t *testing.T) {
	commonName := "example.org"
	template, _ := dummy.Dummy{}.GetTemplate("TestTemplate")
	template.AllowedCNDomains = []string{"notExample.org"}
	err := pki.ValidateCommonName(commonName, template)
	if err.Error() != "The common name is not in any of the domains permitted by the requested template" {
		t.Errorf("Incorrect error message. %s", err)
	}
}

func TestDnsNameValidateSubjectAltNames(t *testing.T) {
	dnsNames := []string{"example.org"}
	emailAddresses := []string{}
	ipAddresses := []net.IP{}
	URIs := []*url.URL{}
	template, _ := dummy.Dummy{}.GetTemplate("TestTemplate")
	template.PermDNSDomains = dnsNames
	template.ExclDNSDomains = []string{"exludedDomain"}

	err := pki.ValidateSubjectAltNames(dnsNames, emailAddresses, ipAddresses, URIs, template)
	if err != nil {
		t.Errorf("Error occured even though it should not. %s", err)
	}
}
