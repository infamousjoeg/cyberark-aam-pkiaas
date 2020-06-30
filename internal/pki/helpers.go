package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"math/bits"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/golang/gddo/httputil/header"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

var minRSASize = 2048
var ocspServer = []string{"OCSPURLField"}
var issuingCertificateURL = []string{"IssuingCertificateURL"}
var crlDistributionPoints = []string{"CRLDistributionPoints"}

// Pki --------------------------------------------------------------------------
// A simple struct to house all the interfaces that are needed by the PKI service
type Pki struct {
	Backend backend.Storage
}

func getMaxRsaKeySize() int {
	value := os.Getenv("PKI_RSA_MAX_KEY_SIZE")
	intValue, err := strconv.Atoi(value)
	// If the environment variable cannot be converted into an integer
	// return the default value
	if err != nil {
		return 8192
	}
	return intValue
}

// GenerateKeys -----------------------------------------------------------------
// Accepts a key algorithm and key bit size as arguments, and then generates the appropriate
// private and public key based on inputs.
func GenerateKeys(keyAlgo string, keySize string) (crypto.PrivateKey, crypto.PublicKey, error) {
	switch strings.ToUpper(keyAlgo) {
	case "RSA":
		bits, err := strconv.Atoi(keySize)
		if err != nil {
			return nil, nil, errors.New("The key size for RSA keys is required to be an integer greater than " + strconv.Itoa(minRSASize) + " bits")
		}
		if bits < minRSASize {
			return nil, nil, errors.New("The minimum supported size for RSA keys is " + strconv.Itoa(minRSASize) + " bits")
		}
		if bits > getMaxRsaKeySize() {
			return nil, nil, errors.New("The maximum supported size for RSA keys is " + strconv.Itoa(getMaxRsaKeySize()) + " bits")
		}
		clientPrivKey, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil, errors.New("Error generating private key: " + err.Error())
		}
		clientPubKey := clientPrivKey.Public()
		return clientPrivKey, clientPubKey, nil
	case "ECDSA":
		var curve elliptic.Curve
		switch keySize {
		case "p224":
			curve = elliptic.P224()
		case "p256":
			curve = elliptic.P256()
		case "p384":
			curve = elliptic.P384()
		case "p521":
			curve = elliptic.P521()
		default:
			return nil, nil, errors.New("The valid key sizes for ECDSA keys are: p224, p256, p384, or p521")
		}
		clientPrivKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, errors.New("Error generating private key: " + err.Error())
		}
		clientPubKey := clientPrivKey.Public()
		return clientPrivKey, clientPubKey, nil
	case "ED25519":
		clientPubKey, clientPrivKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, errors.New("Error generating private key: " + err.Error())
		}
		return clientPrivKey, clientPubKey, nil
	default:
		return nil, nil, errors.New("The provided key algorithm is not valid")

	}
}

// GenerateSerialNumber ---------------------------------------------------------
// Generates a new serial number and validates it doesn't already exist in the certificate
// store
func GenerateSerialNumber(backend backend.Storage) (*big.Int, error) {
	maxValue := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, maxValue)
	if err != nil {
		return big.NewInt(0), errors.New("Error creating serial number: " + err.Error())
	}
	// Test the created serial number against the serial numbers stored in the backend
	// and continue looping, creating, and testing serial numbers until a unique one
	// is generated
	i := 0
	for _, err := backend.GetCertificate(serialNumber); err == nil; {
		serialNumber, err = rand.Int(rand.Reader, maxValue)
		if err != nil {
			return big.NewInt(0), errors.New("Error creating serial number: " + err.Error())
		}
		if i > 2 {
			break
		}
		i++
	}
	return serialNumber, nil
}

// ValidateContentType ---------------------------------------------------------
// Helper function to ensure that the Content-Type of a given HTTP request matches
// what is expected by the API
func ValidateContentType(headers http.Header, expected string) bool {
	if headers.Get("Content-Type") != "" {
		value, _ := header.ParseValueAndParams(headers, "Content-Type")
		if value != expected {
			return false
		}
		return true
	}
	return false
}

// ProcessKeyUsages ------------------------------------------------------------
// Reads descriptive x509 key usage strings from an array and generates
// a bitwise x509.KeyUsage object with the appropriate bits set
func ProcessKeyUsages(keyUsages []string) (x509.KeyUsage, error) {
	var retKeyUsage x509.KeyUsage

	for _, keyUsage := range keyUsages {
		switch keyUsage {
		case "digitalSignature":
			retKeyUsage |= x509.KeyUsageDigitalSignature
		case "keyEncipherment":
			retKeyUsage |= x509.KeyUsageKeyEncipherment
		case "dataEncipherment":
			retKeyUsage |= x509.KeyUsageDataEncipherment
		case "contentCommitment":
			retKeyUsage |= x509.KeyUsageContentCommitment
		case "keyAgreement":
			retKeyUsage |= x509.KeyUsageKeyAgreement
		case "certSign":
			retKeyUsage |= x509.KeyUsageCertSign
		case "crlSign":
			retKeyUsage |= x509.KeyUsageCRLSign
		case "encipherOnly":
			retKeyUsage |= x509.KeyUsageEncipherOnly
		case "decipherOnly":
			retKeyUsage |= x509.KeyUsageDecipherOnly
		default:
			return retKeyUsage, errors.New(keyUsage + " is not a valid key usage")
		}
	}
	return retKeyUsage, nil
}

// ValidateKeyUsageConstraints --------------------------------------------------
// Reads the key usages from a CSR and ensures that none of the CSR's requested key
// usage fields have been excluded by the template that is being associated with the
// certificate signing request
func ValidateKeyUsageConstraints(csrKeyUsage []byte, templateKeyUsage []string) (x509.KeyUsage, error) {
	var retUsage uint16
	var bsAllowedUsage, csrUsage asn1.BitString

	// Capture the key usages that are permitted by the supplied template
	allowedUsages, err := ProcessKeyUsages(templateKeyUsage)
	if err != nil {
		return 0, errors.New("Error processing key usages from template: " + err.Error())
	}

	// Reverse the bits of the allowed usages integer to account for big-endian ASN.1 bit string
	// that it will be compared against
	allowedUsages = x509.KeyUsage(bits.Reverse16(uint16(allowedUsages)))
	bsAllowedUsage.BitLength = 9
	// Bitwise separation of the 16-bit allowedUsages variable into a 2-byte byte slice
	// to be compared against the CSR's key usages
	bsAllowedUsage.Bytes = []byte{byte(0xff & (allowedUsages >> 8)), byte(0xff & allowedUsages)}
	_, err = asn1.Unmarshal(csrKeyUsage, &csrUsage)
	if err != nil {
		return 0, errors.New("Unable to unmarshal ASN.1 encoded key usage data: " + err.Error())
	}
	// Verification that, if it is set, the given key usage is also set in the allowed usages
	for i := 0; i < csrUsage.BitLength; i++ {
		if csrUsage.At(i) == 1 && csrUsage.At(i) != bsAllowedUsage.At(i) {
			return 0, errors.New("The CSR contains key usages that are not permitted")
		}
	}

	// Create a big endian integer representation of the csrUsage, convert it to little endian
	// and return the key usages extracted from the CSR
	retUsage = binary.BigEndian.Uint16(csrUsage.Bytes)
	retUsage = bits.Reverse16(retUsage)
	return x509.KeyUsage(retUsage), nil
}

// ProcessExtKeyUsages ----------------------------------------------------------
// Reads descriptive x509 extended key usage strings from an array and generates
// an array of x509.ExtKeyUsage types that are converted to from the strings
func ProcessExtKeyUsages(extKeyUsages []string) ([]x509.ExtKeyUsage, error) {
	retExtKeyUsage := []x509.ExtKeyUsage{}

	for _, extKeyUsage := range extKeyUsages {
		switch extKeyUsage {
		case "any":
			retExtKeyUsage = append(retExtKeyUsage, x509.ExtKeyUsageAny)
		case "serverAuth":
			retExtKeyUsage = append(retExtKeyUsage, x509.ExtKeyUsageServerAuth)
		case "clientAuth":
			retExtKeyUsage = append(retExtKeyUsage, x509.ExtKeyUsageClientAuth)
		case "codeSigning":
			retExtKeyUsage = append(retExtKeyUsage, x509.ExtKeyUsageCodeSigning)
		case "emailProtection":
			retExtKeyUsage = append(retExtKeyUsage, x509.ExtKeyUsageEmailProtection)
		case "timeStamping":
			retExtKeyUsage = append(retExtKeyUsage, x509.ExtKeyUsageTimeStamping)
		case "OCSPSigning":
			retExtKeyUsage = append(retExtKeyUsage, x509.ExtKeyUsageOCSPSigning)
		case "ipsecEndSystem":
			retExtKeyUsage = append(retExtKeyUsage, x509.ExtKeyUsageIPSECEndSystem)
		case "ipsecTunnel":
			retExtKeyUsage = append(retExtKeyUsage, x509.ExtKeyUsageIPSECTunnel)
		case "ipsecUser":
			retExtKeyUsage = append(retExtKeyUsage, x509.ExtKeyUsageIPSECUser)
		case "msSGC":
			retExtKeyUsage = append(retExtKeyUsage, x509.ExtKeyUsageMicrosoftServerGatedCrypto)
		case "nsSGC":
			retExtKeyUsage = append(retExtKeyUsage, x509.ExtKeyUsageNetscapeServerGatedCrypto)
		case "msCodeCom":
			retExtKeyUsage = append(retExtKeyUsage, x509.ExtKeyUsageMicrosoftCommercialCodeSigning)
		case "msCodeKernel":
			retExtKeyUsage = append(retExtKeyUsage, x509.ExtKeyUsageMicrosoftKernelCodeSigning)
		default:
			return retExtKeyUsage, errors.New(extKeyUsage + " is not a valid extended key usage")
		}
	}
	return retExtKeyUsage, nil
}

// ValidateExtKeyUsageConstraints -----------------------------------------------
// Reads the key extended usages from a CSR and ensures that none of the CSR's
// requested extended key usage fields have been excluded by the template that
// is being associated with the certificate signing request
func ValidateExtKeyUsageConstraints(csrExtKeyUsage []byte, templateExtKeyUsage []string) ([]x509.ExtKeyUsage, error) {

	// Create a valid x509.ExtKeyUsage object of the extended key usages allowed by the template
	allowedUsage, err := ProcessExtKeyUsages(templateExtKeyUsage)
	retUsage := []x509.ExtKeyUsage{}
	if err != nil {
		return []x509.ExtKeyUsage{}, errors.New("Error processing extended key usages from template: " + err.Error())
	}

	// Read the DER encoded extended usage string from the CSR into an array of ASN.1 encoded OIDs
	var csrExtKeyUsageOid []asn1.ObjectIdentifier
	_, err = asn1.Unmarshal(csrExtKeyUsage, &csrExtKeyUsageOid)
	if err != nil {
		return []x509.ExtKeyUsage{}, errors.New("Error unmarshaling the ASN.1 encoded extended key usage data")
	}
	// Match the specific OIDs to the associated extended key usages and ensure that the given extended key usage
	// is present in the allowed usages from the template
	for i := 0; i < len(csrExtKeyUsageOid); i++ {
		extAllowed := false
		for j := 0; j < len(allowedUsage); j++ {
			switch csrExtKeyUsageOid[i].String() {
			case "1.3.6.1.5.5.7.3.1":
				if allowedUsage[j] == x509.ExtKeyUsageServerAuth {
					extAllowed = true
					retUsage = append(retUsage, x509.ExtKeyUsageServerAuth)
				}
			case "1.3.6.1.5.5.7.3.2":
				if allowedUsage[j] == x509.ExtKeyUsageClientAuth {
					extAllowed = true
					retUsage = append(retUsage, x509.ExtKeyUsageClientAuth)
				}
			case "1.3.6.1.5.5.7.3.3":
				if allowedUsage[j] == x509.ExtKeyUsageCodeSigning {
					extAllowed = true
					retUsage = append(retUsage, x509.ExtKeyUsageCodeSigning)
				}
			case "1.3.6.1.5.5.7.3.4":
				if allowedUsage[j] == x509.ExtKeyUsageEmailProtection {
					extAllowed = true
					retUsage = append(retUsage, x509.ExtKeyUsageEmailProtection)
				}
			case "1.3.6.1.5.5.7.3.5":
				if allowedUsage[j] == x509.ExtKeyUsageIPSECEndSystem {
					extAllowed = true
					retUsage = append(retUsage, x509.ExtKeyUsageIPSECEndSystem)
				}
			case "1.3.6.1.5.5.7.3.6":
				if allowedUsage[j] == x509.ExtKeyUsageIPSECTunnel {
					extAllowed = true
					retUsage = append(retUsage, x509.ExtKeyUsageIPSECTunnel)
				}
			case "1.3.6.1.5.5.7.3.7":
				if allowedUsage[j] == x509.ExtKeyUsageIPSECUser {
					extAllowed = true
					retUsage = append(retUsage, x509.ExtKeyUsageIPSECUser)
				}
			case "1.3.6.1.5.5.7.3.8":
				if allowedUsage[j] == x509.ExtKeyUsageTimeStamping {
					extAllowed = true
					retUsage = append(retUsage, x509.ExtKeyUsageTimeStamping)
				}
			case "1.3.6.1.5.5.7.3.9":
				if allowedUsage[j] == x509.ExtKeyUsageOCSPSigning {
					extAllowed = true
					retUsage = append(retUsage, x509.ExtKeyUsageOCSPSigning)
				}
			case "1.3.6.1.4.1.311.10.3.3":
				if allowedUsage[j] == x509.ExtKeyUsageMicrosoftServerGatedCrypto {
					extAllowed = true
					retUsage = append(retUsage, x509.ExtKeyUsageMicrosoftServerGatedCrypto)
				}
			case "2.16.840.1.113730.4.1":
				if allowedUsage[j] == x509.ExtKeyUsageNetscapeServerGatedCrypto {
					extAllowed = true
					retUsage = append(retUsage, x509.ExtKeyUsageNetscapeServerGatedCrypto)
				}
			case "1.3.6.1.4.1.311.2.1.22":
				if allowedUsage[j] == x509.ExtKeyUsageMicrosoftCommercialCodeSigning {
					extAllowed = true
					retUsage = append(retUsage, x509.ExtKeyUsageMicrosoftCommercialCodeSigning)
				}
			default:
				return []x509.ExtKeyUsage{}, errors.New("The CSR contains extended key usages that are not permitted")
			}
		}
		if !extAllowed {
			return []x509.ExtKeyUsage{}, errors.New("The CSR contains extended key usages that are not permitted")
		}
	}
	return retUsage, nil
}

// SetCertSubject -----------------------------------------------------------------
// Reads the subject fields from a type.SubjectFields object that has been filled with
// parsed JSON from a HTTP request and converts it, along with a common name, to a
// pkix.Name object for ingestion by a certificate or certificate request
func SetCertSubject(subject types.SubjectFields, commonName string) (pkix.Name, error) {
	var subjectName pkix.Name

	if subject.Country != "" {
		subjectName.Country = []string{subject.Country}
	}
	if subject.Organization != "" {
		subjectName.Organization = []string{subject.Organization}
	}
	if subject.OrgUnit != "" {
		subjectName.OrganizationalUnit = []string{subject.OrgUnit}
	}
	if subject.Locality != "" {
		subjectName.Locality = []string{subject.Locality}
	}
	if subject.Province != "" {
		subjectName.Province = []string{subject.Province}
	}
	if subject.Address != "" {
		subjectName.StreetAddress = []string{subject.Address}
	}
	if subject.PostalCode != "" {
		subjectName.PostalCode = []string{subject.PostalCode}
	}
	if commonName == "" {
		return pkix.Name{}, errors.New("Common name is a required Subject field")
	}
	subjectName.CommonName = commonName
	return subjectName, nil
}

// PrepareCertificateParameters ---------------------------------------------------
// Catch-all helper method to isolate redundant code that is used to set parameters
// that are used when creating a new certificate
func PrepareCertificateParameters(templateName string, reqTTL int64, backend backend.Storage) (types.Template, *big.Int, int64, x509.SignatureAlgorithm, *x509.Certificate, crypto.PrivateKey, error) {
	template, err := backend.GetTemplate(templateName)
	if err != nil {
		return types.Template{}, nil, 0, 0, nil, nil, errors.New("Error retrieving template from backend: " + err.Error())
	}

	serialNumber, err := GenerateSerialNumber(backend)
	if err != nil {
		return types.Template{}, nil, 0, 0, nil, nil, errors.New("Error generating serial number: " + err.Error())
	}

	// Set the TTL value to either that which was request or the max TTL allowed by the template
	// in the event that the requested TTL was greater
	var ttl int64
	if reqTTL < template.MaxTTL {
		ttl = reqTTL
	} else {
		ttl = template.MaxTTL
	}

	// Retrieve the intermediate CA certificate from backend and go through the necessary steps
	// to convert it from a PEM-string to a usable x509.Certificate object
	strCert, err := backend.GetSigningCert()
	if err != nil {
		return types.Template{}, nil, 0, 0, nil, nil, errors.New("Error retrieving signing certificate from backend: " + err.Error())
	}

	derCACert, err := base64.StdEncoding.DecodeString(strCert)
	if err != nil {
		return types.Template{}, nil, 0, 0, nil, nil, errors.New("Error decoding signing certificate: " + err.Error())
	}
	caCert, err := x509.ParseCertificate(derCACert)
	if err != nil {
		return types.Template{}, nil, 0, 0, nil, nil, errors.New("Error parsing decoded signing certificate: " + err.Error())
	}

	// Validate that requested certificate is within validity period of CA certificate
	if caCert.NotAfter.Sub(time.Now().Add(time.Minute*time.Duration(ttl)).UTC()) < 0 {
		return types.Template{}, nil, 0, 0, nil, nil, errors.New("Requested certificate validity period is greater than the CA validity period")
	}

	// Retrieve the signing key from backend and calculate the signature algorithm for use in the
	// certificate generation
	strKey, err := backend.GetSigningKey()
	if err != nil {
		return types.Template{}, nil, 0, 0, nil, nil, errors.New("Error retrieving signing key from backend: " + err.Error())
	}

	decodedKey, err := base64.StdEncoding.DecodeString(strKey)
	if err != nil {
		return types.Template{}, nil, 0, 0, nil, nil, errors.New("Error decoding signing key: " + err.Error())
	}
	// Try to parse the private key using PKCS8, and if it fails attempt to use the recommended
	// parsing format from the PKCS8 error
	signingKey, err := x509.ParsePKCS8PrivateKey(decodedKey)
	if err != nil {
		if strings.Contains(err.Error(), "ParsePKCS1PrivateKey") {
			signingKey, err = x509.ParsePKCS1PrivateKey(decodedKey)
			if err != nil {
				return types.Template{}, nil, 0, 0, nil, nil, errors.New("Error parsing RSA signing key: " + err.Error())
			}
		} else {
			return types.Template{}, nil, 0, 0, nil, nil, errors.New("Unable to determine signing key type: " + err.Error())
		}
	}

	keyType := fmt.Sprintf("%T", signingKey)
	var sigAlgo x509.SignatureAlgorithm
	switch keyType {
	case "*rsa.PrivateKey":
		sigAlgo = x509.SHA256WithRSA
	case "*ecdsa.PrivateKey":
		sigAlgo = x509.ECDSAWithSHA256
	case "ed25519.PrivateKey":
		sigAlgo = x509.PureEd25519
	default:
		return types.Template{}, nil, 0, 0, nil, nil, errors.New("Unable to determine signing key type")
	}
	return template, serialNumber, ttl, sigAlgo, caCert, signingKey, nil
}

// ProcessSubjectAltNames ---------------------------------------------------------
func ProcessSubjectAltNames(altNames []string) ([]string, []string, []net.IP, []*url.URL, error) {
	dnsNames, emailAddresses, ipAddresses, URIs := []string{}, []string{}, []net.IP{}, []*url.URL{}
	// Regex to match email address formats
	var rxEmail = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

	for _, altName := range altNames {
		if !strings.Contains(altName, ":") {
			return dnsNames, emailAddresses, ipAddresses, URIs, errors.New("Improperly formatted SAN present in request: " + altName)
		}
		switch strings.Split(altName, ":")[0] {
		case "IP":
			tempIP := net.ParseIP(strings.Split(altName, ":")[1])
			if tempIP == nil {
				return dnsNames, emailAddresses, ipAddresses, URIs, errors.New("Invalid IP address SAN present in request: " + strings.Split(altName, ":")[1])
			}
			ipAddresses = append(ipAddresses, tempIP)
		case "DNS":
			dnsNames = append(dnsNames, strings.Split(altName, ":")[1])
		case "email":
			if !rxEmail.MatchString(strings.Split(altName, ":")[1]) {
				return dnsNames, emailAddresses, ipAddresses, URIs, errors.New("Invalid email address SAN present in request: " + strings.Split(altName, ":")[1])
			}
			emailAddresses = append(emailAddresses, strings.Split(altName, ":")[1])
		case "URI":
			tempURI, err := url.ParseRequestURI(strings.Split(altName, "RI:")[1])
			if err != nil {
				return dnsNames, emailAddresses, ipAddresses, URIs, errors.New("Invalid URI SAN present in request: " + err.Error())
			}
			URIs = append(URIs, tempURI)
		default:
			return dnsNames, emailAddresses, ipAddresses, URIs, errors.New("Improperly formatted SAN present in request: " + altName)
		}
	}
	return dnsNames, emailAddresses, ipAddresses, URIs, nil
}

// ValidateCommonName -------------------------------------------------------------
// Ensure the CommonName passed in a certificate creation request adheres to all the
// standards defined in the requested template
func ValidateCommonName(commonName string, template types.Template) error {

	if template.ValidateCNHostname {
		re := regexp.MustCompile("^[a-zA-Z0-9.*-]*$")
		if !re.MatchString(commonName) {
			return errors.New("Common Name is not a valid hostname; valid hostname is required by template")
		}
	}

	if !template.PermitLocalhostCN {
		if commonName == "localhost" || commonName == "localdomain" {
			return errors.New("The requested template does not permit " + commonName + " as a common name")
		}
	}

	if !template.PermitWildcardCN {
		if strings.Contains(commonName, "*") {
			return errors.New("The requested template does not permit wildcards")
		}
	}

	if len(template.AllowedCNDomains) > 0 {
		cnHost := strings.Split(commonName, ".")[0]
		cnDomain := strings.Replace(commonName, cnHost, "", 1)
		valid := false
		for _, domain := range template.AllowedCNDomains {
			if !template.PermitRootDomainCN && commonName == domain {
				return errors.New("The request template does not permit the certificate common name to be the root domain")
			}
			if template.PermitSubdomainCN {
				if strings.Contains(domain, cnDomain) {
					valid = true
				}
			} else {
				if domain == cnDomain {
					valid = true
				}
			}

		}
		if !valid {
			return errors.New("The common name is not in any of the domains permitted by the requested template")
		}
	}

	return nil
}

// ValidateSubjectAltNames --------------------------------------------------------
// Loops through all DNS Names, Email Addresses, IP Addresses, and URIs presented
// as Subject Alternative Names for a certificate and validates that they are not
// explicitly excluded from being valid based on the template, as well as ensuring
// that, if the template has defined permitted SANs, the request is permitted
func ValidateSubjectAltNames(dnsNames []string, emailAddresses []string, ipAddresses []net.IP, URIs []*url.URL, template types.Template) error {

	if len(template.PermIPRanges) > 0 {
		// Loop through all the IP address ranges, extract the subnet associated with each IP address from the SAN request
		// and validate that the subnet matches one or more of the permitted IP ranges
		for _, network := range template.PermIPRanges {
			for _, address := range ipAddresses {
				permitted := false
				_, ipNet, err := net.ParseCIDR(network)
				if err != nil {
					return errors.New("Error parsing permitted IP network ranges")
				}
				if ipNet.Contains(address) {
					permitted = true
				}
				if !permitted {
					return errors.New("IP address SAN in request is not in permitted IP ranges")
				}
			}
		}
	}
	if len(template.ExclIPRanges) > 0 {
		// Loop through all the IP address ranges, extract the subnet associated with each IP address from the SAN request
		// and validate that none of the subnets match any of the excluded IP ranges
		for _, network := range template.PermIPRanges {
			for _, address := range ipAddresses {
				excluded := false
				_, ipNet, err := net.ParseCIDR(network)
				if err != nil {
					return errors.New("Error parsing excluded IP network ranges")
				}
				if ipNet.Contains(address) {
					excluded = true
				}
				if excluded {
					return errors.New("IP address SAN in request is in the excluded IP ranges")
				}
			}
		}
	}

	// Regex to match email address formats
	var rxEmail = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	if len(template.PermEmails) > 0 {
		// Loop through all the permitted email addresses, validate the email address from the
		// SAN request is actually an email address, and validate that the email address matches
		// at least one of the permitted email addresses or email domains
		for _, permEmail := range template.PermEmails {
			for _, email := range emailAddresses {
				permitted := false
				if rxEmail.MatchString(permEmail) {
					if email == permEmail {
						permitted = true
					}
				} else {
					if len(email) > len(permEmail) {
						if string(email[len(email)-len(permEmail):]) == permEmail {
							permitted = true
						}
					}
				}
				if !permitted {
					return errors.New("Email address SAN in request is not in permitted emails")
				}
			}
		}
	}
	if len(template.ExclEmails) > 0 {
		// Loop through all the excluded email addresses, validate the email address from the
		// SAN request is actually an email address, and validate that the email address does
		// not match any of the excluded email addresses or email domains
		for _, exclEmail := range template.ExclEmails {
			for _, email := range emailAddresses {
				excluded := false
				if rxEmail.MatchString(exclEmail) {
					if email == exclEmail {
						excluded = true
					}
				} else {
					if len(email) > len(exclEmail) {
						if string(email[len(email)-len(exclEmail):]) == exclEmail {
							excluded = true
						}
					}
				}
				if excluded {
					return errors.New("Email address SAN in request is in excluded emails")
				}
			}
		}
	}

	if len(template.PermDNSDomains) > 0 {
		// Loop through all the permitted DNS domains and validate that the domain matches
		// at least one of the permitted DNS domains
		for _, permDNS := range template.PermDNSDomains {
			for _, dns := range dnsNames {
				permitted := false
				if len(dns) > len(permDNS) {
					if string(dns[len(dns)-len(permDNS):]) == permDNS {
						permitted = true
					}
				}
				if !permitted {
					return errors.New("DNS SAN in request is not in permitted DNS domains")
				}
			}
		}
	}
	if len(template.ExclDNSDomains) > 0 {
		// Loop through all the excluded DNS domains and validate that the domain does not
		// match any of the excluded DNS domains
		for _, exclDNS := range template.ExclDNSDomains {
			for _, dns := range dnsNames {
				excluded := false
				if len(dns) > len(exclDNS) {
					if string(dns[len(dns)-len(exclDNS):]) == exclDNS {
						excluded = true
					}
				}
				if excluded {
					return errors.New("DNS SAN in request is in excluded DNS domains")
				}
			}
		}
	}
	return nil
}

// ProcessPolicyIdentifiers -----------------------------------------------------
// Converts the array that contains string representations of policy OIDs into ASN.1
// format and validates that all policy OID strings that were sent in the request are
// valid
func ProcessPolicyIdentifiers(policyIdentifiers []string) ([]asn1.ObjectIdentifier, error) {
	asn1PolicyID := []asn1.ObjectIdentifier{}
	for _, pid := range policyIdentifiers {
		separated := strings.Split(pid, ".")
		var intPids []int
		for _, elem := range separated {
			temp, err := strconv.Atoi(elem)
			if err != nil {
				return []asn1.ObjectIdentifier{}, errors.New("Policy OID in request is not a valid ASN.1 OID")
			}
			intPids = append(intPids, temp)
		}
		asn1PolicyID = append(asn1PolicyID, intPids)
	}
	return asn1PolicyID, nil
}

// ValidateKeyAlgoAndSize ------------------------------------------------------
// Validates that the request key algorithm is one that is supported by the PKI
// service and that the key size requested is both pertinent to the requested
// algorithm and meets minimum size standards
func ValidateKeyAlgoAndSize(keyAlgo string, keySize string) error {
	switch strings.ToUpper(keyAlgo) {
	case "RSA":
		if keyBits, err := strconv.Atoi(keySize); err != nil || keyBits < minRSASize || keyBits > getMaxRsaKeySize() {
			return errors.New("Invalid key size for key algorithm RSA, must be at least 2048 bits and no larger than " + strconv.Itoa(getMaxRsaKeySize()))
		}
		return nil
	case "ECDSA":
		if keySize != "p224" && keySize != "p256" && keySize != "p384" && keySize != "p521" {
			return errors.New("Invalid key size for key algorithm ECDSA")
		}
		return nil
	case "ED25519":
		return nil
	default:
		return errors.New("No valid key algorithm has been supplied")
	}
}

// ConvertSerialIntToOctetString --------------------------------------------------------
// Receives a X.509 certificate serial number as an integer and converts it to an
// ASN.1 compliant octet string
func ConvertSerialIntToOctetString(intSerialNum *big.Int) (string, error) {
	asn1SerialNum, err := asn1.Marshal(intSerialNum)
	if err != nil {
		return "", errors.New("Error marshaling serial number to ASN.1: " + err.Error())
	}
	retSerialNum := ""
	for i := 1; i < len(asn1SerialNum); i++ {
		if i != 0 {
			temp := fmt.Sprintf("%x", asn1SerialNum[i])
			if len(temp) < 2 {
				temp = "0" + temp
			}
			if retSerialNum == "" {
				retSerialNum = temp
			} else {
				retSerialNum = retSerialNum + ":" + temp
			}
		}
	}
	return retSerialNum, nil
}

// ConvertSerialOctetStringToInt -------------------------------------------------
// Receives a X.509 certificate serial number as an ASN.1 octet string and converts
// it to an integer
func ConvertSerialOctetStringToInt(octetSerialNum string) (*big.Int, error) {
	octets := []byte{}
	octets = append(octets, byte(2))
	if len(strings.Split(octetSerialNum, ":")) > 20 {
		return nil, errors.New("Invalid serial number, max serial number size is 20 octets")
	}
	for _, data := range strings.Split(octetSerialNum, ":") {
		parsedData, err := strconv.ParseUint(data, 16, 8)
		if err != nil {
			return nil, errors.New("Error converting octet string to integer: " + err.Error())
		}
		octets = append(octets, byte(parsedData))
	}
	retSerialNum := new(big.Int)
	_, err := asn1.Unmarshal(octets, &retSerialNum)
	if err != nil {
		return nil, errors.New("Error unmarshaling ASN.1 data to octet string: " + err.Error())
	}
	return retSerialNum, nil
}

// ReturnReasonCode --------------------------------------------------------------
// Converts a string with a certificate revocation reason from a revoke request
// to its corresponding RFC reason code
func ReturnReasonCode(reasonString string) (int, error) {
	switch reasonString {
	case "keyCompromise":
		return 1, nil
	case "cACompromise":
		return 2, nil
	case "affiliationChanged":
		return 3, nil
	case "superseded":
		return 4, nil
	case "cessationOfOperation":
		return 5, nil
	case "certificateHold":
		return 0, errors.New("This endpoint is for certificate revocation. For temporary hold, use HoldCertificate")
	case "removeFromCRL":
		return 0, errors.New("This endpoint is for certificate revocation. To release tenporary hold, use ReleaseCertificate")
	case "privilegeWithdrawn":
		return 9, nil
	case "aACompromise":
		return 10, nil
	default:
		return 0, errors.New("Reason code in request is not acceptable certificate revocation reason")
	}
}
