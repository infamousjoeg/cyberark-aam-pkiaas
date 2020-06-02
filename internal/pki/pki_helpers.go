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
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"math/bits"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/golang/gddo/httputil/header"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// GenerateKeys ----------------------------------------------------------------------
// Accepts a key algorithm and key bit size as arguments, and then generates the appropriate
// private and public key based on inputs.
func GenerateKeys(keyAlgo string, keySize string) (crypto.PrivateKey, crypto.PublicKey, error) {
	switch keyAlgo {
	case "RSA":
		bits, err := strconv.Atoi(keySize)
		if err != nil {
			return nil, nil, errors.New("The key size for the requested template  is not in the appropriate format for RSA keys")
		}
		if bits < 2048 {
			return nil, nil, errors.New("The requested RSA key length is below the minimum supported 2048 bits")
		}
		clientPrivKey, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil, errors.New("Unable to generate private key for new certificate")
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
			return nil, nil, errors.New("The key size for the requested template is not in the appropriate format for ECDSA keys")
		}
		clientPrivKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, errors.New("Unable to generate private key for new certificate")
		}
		clientPubKey := clientPrivKey.Public()
		return clientPrivKey, clientPubKey, nil
	case "ED25519":
		clientPubKey, clientPrivKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, errors.New("Unable to generate private key for new certificate")
		}
		return clientPrivKey, clientPubKey, nil
	default:
		return nil, nil, errors.New("The requested template does not have a valid key algorithm provided")

	}
}

// GenerateSerialNumber ------------------------------------------------------------------
// Generates a new serial number and validates it doesn't already exist in the certificate
// store
func GenerateSerialNumber() (*big.Int, error) {
	maxValue := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, maxValue)
	if err != nil {
		return big.NewInt(0), errors.New("Unable to generate a new serial number")
	}
	for _, err := GetCertFromDAP(serialNumber); err == nil; {
		serialNumber, err = rand.Int(rand.Reader, maxValue)
		if err != nil {
			return big.NewInt(0), errors.New("Unable to generate a new serial number")
		}
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

// ProcessKeyUsages -----------------------------------------------------
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
			return retKeyUsage, errors.New("Invalid key usage type is specified in request")
		}
	}
	return retKeyUsage, nil
}

// ValidateKeyUsageConstraints ---------------------------------------------------
func ValidateKeyUsageConstraints(csrKeyUsage []byte, templateKeyUsage []string) (x509.KeyUsage, error) {
	allowedUsages, err := ProcessKeyUsages(templateKeyUsage)
	var retUsage uint16
	if err != nil {
		return 0, errors.New("There was an error processing the requested template key usages")
	}
	var bsAllowedUsage, csrUsage asn1.BitString
	allowedUsages = x509.KeyUsage(bits.Reverse16(uint16(allowedUsages)))
	bsAllowedUsage.BitLength = 9
	bsAllowedUsage.Bytes = []byte{byte(0xff & (allowedUsages >> 8)), byte(0xff & allowedUsages)}
	_, err = asn1.Unmarshal(csrKeyUsage, &csrUsage)
	if err != nil {
		return 0, errors.New("There was an error unmarshaling the ASN.1 encoded key usage data")
	}
	for i := 0; i < csrUsage.BitLength; i++ {
		if csrUsage.At(i) == 1 && csrUsage.At(i) != bsAllowedUsage.At(i) {
			return 0, errors.New("The requested CSR contains one or more key usages that are not permitted by the template")
		}
	}
	retUsage = binary.BigEndian.Uint16(csrUsage.Bytes)
	retUsage = bits.Reverse16(retUsage)
	return x509.KeyUsage(retUsage), nil
}

// ProcessExtKeyUsages ------------------------------------------------------------
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
			return retExtKeyUsage, errors.New("Invalid extended key usage " + extKeyUsage + " was found in request")
		}
	}
	return retExtKeyUsage, nil
}

// ValidateExtKeyUsageConstraints --------------------------------------------------
func ValidateExtKeyUsageConstraints(csrExtKeyUsage []byte, templateExtKeyUsage []string) ([]x509.ExtKeyUsage, error) {
	allowedUsage, err := ProcessExtKeyUsages(templateExtKeyUsage)
	retUsage := []x509.ExtKeyUsage{}
	if err != nil {
		return []x509.ExtKeyUsage{}, errors.New("There was an error processing the requested template extended key usages")
	}

	var csrExtKeyUsageOid []asn1.ObjectIdentifier
	_, err = asn1.Unmarshal(csrExtKeyUsage, &csrExtKeyUsageOid)
	if err != nil {
		return []x509.ExtKeyUsage{}, errors.New("There was an error unmarshaling the ASN.1 encoded extended key usage data")
	}
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
				return []x509.ExtKeyUsage{}, errors.New("The CSR has requested extended key usages that are not permitted in the given template")
			}
		}
		if !extAllowed {
			return []x509.ExtKeyUsage{}, errors.New("The CSR has requested extended key usages that are not permitted in the given template")
		}
	}
	return retUsage, nil
}

// SetCertSubject -----------------------------------------------------------------
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
		return pkix.Name{}, errors.New("New certificate must have common name provided in the request")
	}
	subjectName.CommonName = commonName
	return subjectName, nil
}

// ProcessSubjectAltNames ---------------------------------------------------------
func ProcessSubjectAltNames(altNames []string) ([]string, []string, []net.IP, []*url.URL, error) {
	dnsNames, emailAddresses, ipAddresses, URIs := []string{}, []string{}, []net.IP{}, []*url.URL{}

	for _, altName := range altNames {
		if !strings.Contains(altName, ":") {
			return dnsNames, emailAddresses, ipAddresses, URIs, errors.New("One of more of the provided SANs is not properly formatted")
		}
		switch strings.Split(altName, ":")[0] {
		case "IP":
			tempIP := net.ParseIP(strings.Split(altName, ":")[1])
			if tempIP == nil {
				return dnsNames, emailAddresses, ipAddresses, URIs, errors.New("An invalid IP address was present in the requested SAN")
			}
			ipAddresses = append(ipAddresses, tempIP)
		case "DNS":

			dnsNames = append(dnsNames, strings.Split(altName, ":")[1])
		case "email":
			emailAddresses = append(emailAddresses, strings.Split(altName, ":")[1])
		case "URI":
			tempURI, err := url.ParseRequestURI(strings.Split(altName, ":")[1])
			if err != nil {
				return dnsNames, emailAddresses, ipAddresses, URIs, errors.New("One or more of the URIs sent in the request were unable to be successfully processed")
			}
			URIs = append(URIs, tempURI)
		default:
			return dnsNames, emailAddresses, ipAddresses, URIs, errors.New("One of more of the provided SANs in the certificate request is not properly formatted")
		}
	}
	return dnsNames, emailAddresses, ipAddresses, URIs, nil
}

// ValidateSubjectAltNames ------------------------------------------------------
func ValidateSubjectAltNames(dnsNames []string, emailAddresses []string, ipAddresses []net.IP, URIs []*url.URL, template types.Template) error {

	if len(template.PermIPRanges) > 0 {
		for _, network := range template.PermIPRanges {
			for _, address := range ipAddresses {
				permitted := false
				_, ipNet, err := net.ParseCIDR(network)
				if err != nil {
					return errors.New("There was an error handling permitted IP network ranges")
				}
				if ipNet.Contains(address) {
					permitted = true
				}
				if !permitted {
					return errors.New("One of more of the IP address SANs were not in the explicitly permitted IP ranges")
				}
			}
		}
	}
	if len(template.ExclIPRanges) > 0 {
		for _, network := range template.PermIPRanges {
			for _, address := range ipAddresses {
				excluded := false
				_, ipNet, err := net.ParseCIDR(network)
				if err != nil {
					return errors.New("There was an error handling permitted IP network ranges")
				}
				if ipNet.Contains(address) {
					excluded = true
				}
				if excluded {
					return errors.New("One of more of the IP address SANs were in the excluded IP ranges")
				}
			}
		}
	}
	var rxEmail = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	if len(template.PermEmails) > 0 {
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
					return errors.New("One of more of the email address SANs were not in the explicitly permitted emails")
				}
			}
		}
	}
	if len(template.ExclEmails) > 0 {
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
					return errors.New("One of more of the email address SANs were in the excluded emails")
				}
			}
		}
	}
	if len(template.PermDNSDomains) > 0 {
		for _, permDNS := range template.PermDNSDomains {
			for _, dns := range dnsNames {
				permitted := false
				if len(dns) > len(permDNS) {
					if string(dns[len(dns)-len(permDNS):]) == permDNS {
						permitted = true
					}
				}
				if !permitted {
					return errors.New("One of more of the DNS domain SANs were not in the explicitly permitted DNS domains")
				}
			}
		}
	}
	if len(template.ExclDNSDomains) > 0 {
		for _, exclDNS := range template.ExclDNSDomains {
			for _, dns := range dnsNames {
				excluded := false
				if len(dns) > len(exclDNS) {
					if string(dns[len(dns)-len(exclDNS):]) == exclDNS {
						excluded = true
					}
				}
				if excluded {
					return errors.New("One of more of the DNS domain SANs were in the excluded DNS domains")
				}
			}
		}
	}
	return nil
}

// ProcessPolicyIdentifiers -----------------------------------------------------
func ProcessPolicyIdentifiers(policyIdentifiers []string) ([]asn1.ObjectIdentifier, error) {
	asn1PolicyID := []asn1.ObjectIdentifier{}
	for _, pid := range policyIdentifiers {
		separated := strings.Split(pid, ".")
		var intPids []int
		for _, elem := range separated {
			temp, err := strconv.Atoi(elem)
			if err != nil {
				return []asn1.ObjectIdentifier{}, errors.New("One or more of the policy identifiers presented is not a valid ASN.1 OID")
			}
			intPids = append(intPids, temp)
		}
		asn1PolicyID = append(asn1PolicyID, intPids)
	}
	return asn1PolicyID, nil
}

// ValidateKeyAlgoAndSize ------------------------------------------------------
func ValidateKeyAlgoAndSize(keyAlgo string, keySize string) error {
	switch keyAlgo {
	case "RSA":
		if keyBits, err := strconv.Atoi(keySize); err != nil || keyBits < 2048 {
			return errors.New("Invalid key size for key algorithm RSA, must be at least 2048 bits")
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
func ConvertSerialIntToOctetString(intSerialNum *big.Int) (string, error) {
	asn1SerialNum, err := asn1.Marshal(intSerialNum)
	if err != nil {
		return "", errors.New("Problem converting serial number integer to ASN.1")
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
func ConvertSerialOctetStringToInt(octetSerialNum string) (*big.Int, error) {
	octets := []byte{}
	octets = append(octets, byte(2))
	if len(strings.Split(octetSerialNum, ":")) > 20 {
		return nil, errors.New("Invalid serial number: too large, maximum x.509 serial number size is 20 octets")
	}
	for _, data := range strings.Split(octetSerialNum, ":") {
		parsedData, err := strconv.ParseUint(data, 16, 8)
		if err != nil {
			return nil, errors.New("Unable to convert serial number octet to integer")
		}
		octets = append(octets, byte(parsedData))
	}
	retSerialNum := new(big.Int)
	asn1.Unmarshal(octets, &retSerialNum)
	return retSerialNum, nil
}

// ReturnReasonCode --------------------------------------------------------------
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
		return 0, errors.New("The requested reason code does not match any acceptable reasons for certificate revocation")
	}
}
