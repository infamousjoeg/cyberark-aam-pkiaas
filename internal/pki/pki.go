package certhelper

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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/golang/gddo/httputil/header"
	"github.com/gorilla/mux"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// CreateTemplateHandler ---------------------------------------------------
func CreateTemplateHandler(w http.ResponseWriter, r *http.Request) {
	reqBody, err := ioutil.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}

	if !ValidateContentType(r.Header, "application/json") {
		http.Error(w, "Invalid content type: expected application/json", http.StatusUnsupportedMediaType)
		return
	}

	var newTemplate types.Template
	err = json.Unmarshal(reqBody, &newTemplate)
	if err != nil {
		http.Error(w, "Unable to process request body data.  JSON Unmarshal returned error: "+err.Error(), http.StatusBadRequest)
		return
	}
	err = ValidateKeyAlgoAndSize(newTemplate.KeyAlgo, newTemplate.KeyBits)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	// Validate and sanitize Subject data

	_, err = ProcessKeyUsages(newTemplate.KeyUsages)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	_, err = ProcessExtKeyUsages(newTemplate.ExtKeyUsages)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	// Validate permitted/excluded data
	_, err = ProcessPolicyIdentifiers(newTemplate.PolicyIdentifiers)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	CreateTemplateInDAP(newTemplate)
}

// ManageTemplateHandler -------------------------------------------------------
func ManageTemplateHandler(w http.ResponseWriter, r *http.Request) {
	reqBody, err := ioutil.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}

	if !ValidateContentType(r.Header, "application/json") {
		http.Error(w, "Invalid content type: expected application/json", http.StatusUnsupportedMediaType)
		return
	}

	var newTemplate types.Template
	err = json.Unmarshal(reqBody, &newTemplate)
	if err != nil {
		http.Error(w, "Unable to process request body data.  JSON Unmarshal returned error: "+err.Error(), http.StatusBadRequest)
		return
	}

	//	oldTemplate, err := GetTemplateFromDAP(newTemplate.TemplateName)
	oldTemplate := types.Template{}
	if err != nil {
		http.Error(w, "The requested template "+newTemplate.TemplateName+" cannot be located", http.StatusBadRequest)
	}
	rNewTemplate := reflect.ValueOf(newTemplate)
	rOldTemplate := reflect.ValueOf(&oldTemplate)
	rOldTemplate = rOldTemplate.Elem()
	typeTemplate := rNewTemplate.Type()
	for i := 0; i < rNewTemplate.NumField(); i++ {
		if rNewTemplate.Field(i).Interface() != "" {
			fieldName := typeTemplate.Field(i).Name
			newField := rOldTemplate.FieldByName(fieldName)
			newValue := rNewTemplate.Field(i).Interface().(string)
			newField.SetString(newValue)
		}
	}
}

// DeleteTemplateHandler -------------------------------------------------------
func DeleteTemplateHandler(w http.ResponseWriter, r *http.Request) {
	template, err := GetTemplateFromDAP(mux.Vars(r)["templateName"])

	if err != nil {
		http.Error(w, "Requested template does not exist", http.StatusBadRequest)
	}
	err = DeleteTemplateFromDAP(template)
	if err != nil {
		http.Error(w, "Unable to delete requested template", http.StatusInternalServerError)
	}
}

// GetTemplateHandler ----------------------------------------------------------
func GetTemplateHandler(w http.ResponseWriter, r *http.Request) {
	template, err := GetTemplateFromDAP(mux.Vars(r)["templateName"])

	if err != nil {
		http.Error(w, "Unable to retrieve requested template", http.StatusBadRequest)
	}
	respTemplate, err := json.Marshal(template)

	if err != nil {
		http.Error(w, "The requested template was unable to be successfully processed into a response", http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(respTemplate)
}

// ListTemplatesHandler ---------------------------------------------------------
func ListTemplatesHandler(w http.ResponseWriter, r *http.Request) {
	//	templates, err := GetAllTemplatesFromDAP()

	var err error = nil
	if err != nil {
		http.Error(w, "Failed to retrieve a list of templates", http.StatusBadRequest)
	}
}

// SignCertHandler -------------------------------------------------------------
func SignCertHandler(w http.ResponseWriter, r *http.Request) {
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}
	if !ValidateContentType(r.Header, "application/json") {
		http.Error(w, "Invalid content type: expected application/json", http.StatusUnsupportedMediaType)
		return
	}
	var signReq types.SignRequest
	err = json.Unmarshal(reqBody, &signReq)
	certReq, err := x509.ParseCertificateRequest([]byte(signReq.CSR))
	fmt.Printf("%+v", certReq)
}

// CreateCertHandler -----------------------------------------------------------
// Handler function invoked by the API endpoint 'CreateCert', which is responsible
// for building a new certificate with the provided common name based upon the
// provided template
func CreateCertHandler(w http.ResponseWriter, r *http.Request) {
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}
	if !ValidateContentType(r.Header, "application/json") {
		http.Error(w, "Invalid content type: expected application/json", http.StatusUnsupportedMediaType)
		return
	}
	var certReq types.CreateCertReq
	err = json.Unmarshal(reqBody, &certReq)
	if err != nil {
		http.Error(w, "Unable to process request body data.  JSON Unmarshal returned error: "+err.Error(), http.StatusBadRequest)
		return
	}
	template, err := GetTemplate(certReq.TemplateName)

	clientPrivKey, clientPubKey, err := GenerateKeys(template.KeyAlgo, template.KeyBits)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Println(clientPubKey)
	fmt.Println(clientPrivKey)

	var ttl int64
	serialNumber, err := GenSerialNum()
	if certReq.TTL < template.MaxTTL {
		ttl = certReq.TTL
	} else {
		ttl = template.MaxTTL
	}

	caCert, err := GetCACert()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	//	signingKey, err := GetSigningKeyFromDAP()
	var signingKey crypto.PrivateKey

	var sigAlgo x509.SignatureAlgorithm
	switch template.KeyAlgo {
	case "RSA":
		sigAlgo = x509.SHA256WithRSA
	case "ECDSA":
		sigAlgo = x509.ECDSAWithSHA256
	case "ED25519":
		sigAlgo = x509.PureEd25519
	default:
		http.Error(w, "No matching signature algorithm found in requested template", http.StatusInternalServerError)
	}

	keyUsage, err := ProcessKeyUsages(template.KeyUsages)
	extKeyUsage, err := ProcessExtKeyUsages(template.ExtKeyUsages)

	newCert := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{template.Country},
			Organization:       []string{template.Organization},
			OrganizationalUnit: []string{template.OrgUnit},
			Locality:           []string{template.Locality},
			Province:           []string{template.Province},
			StreetAddress:      []string{template.Address},
			PostalCode:         []string{template.PostalCode},
			CommonName:         certReq.CommonName,
		},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(time.Second * time.Duration(ttl)),
		SignatureAlgorithm: sigAlgo,
		AuthorityKeyId:     caCert.SubjectKeyId,
		KeyUsage:           keyUsage,
		ExtKeyUsage:        extKeyUsage,
	}
	derCert, err := x509.CreateCertificate(rand.Reader, &newCert, &caCert, clientPubKey, signingKey)

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
	pemCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.RawTBSCertificate})
	var pemPrivKey []byte

	switch template.KeyAlgo {
	case "RSA":
		pemPrivKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientPrivKey.(*rsa.PrivateKey))})
	case "ECDSA":
		ecKey, _ := x509.MarshalECPrivateKey(clientPrivKey.(*ecdsa.PrivateKey))
		pemPrivKey = pem.EncodeToMemory(&pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: ecKey})
	case "ED25519":
		pemPrivKey = pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: clientPrivKey.(ed25519.PrivateKey)})
	}
	w.Header().Set("Content-Type", "application/json")
	response := types.CertificateResponse{
		Certificate:   string(pemCert),
		PrivateKey:    string(pemPrivKey),
		CACert:        string(pemCA),
		SerialNumber:  serialNumber,
		LeaseDuration: ttl,
	}

	json.NewEncoder(w).Encode(response)

}

// GetCertHandler --------------------------------------------------------------------
func GetCertHandler(w http.ResponseWriter, r *http.Request) {

}

// ListCertsHandler ------------------------------------------------------------------
func ListCertsHandler(w http.ResponseWriter, r *http.Request) {

}

// RevokeCertHandler -----------------------------------------------------------------
func RevokeCertHandler(w http.ResponseWriter, r *http.Request) {

}

// GetCAHandler ----------------------------------------------------------------------
func GetCAHandler(w http.ResponseWriter, r *http.Request) {

}

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
		clientPrivKey, clientPubKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, errors.New("Unable to generate private key for new certificate")
		}
		return clientPrivKey, clientPubKey, nil
	default:
		return nil, nil, errors.New("The requested template does not have a valid key algorithm provided")

	}
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
		case "CertSign":
			retKeyUsage |= x509.KeyUsageCertSign
		case "CRLSign":
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

// ProcessSubjectAltNames ---------------------------------------------------------
func ProcessSubjectAltNames(altNames []string) ([]string, []string, []net.IP, []url.URL, error) {
	dnsNames, emailAddresses, ipAddresses, URIs := []string{}, []string{}, []net.IP{}, []url.URL{}

	for _, altName := range altNames {
		if !strings.Contains(altName, ":") {
			return dnsNames, emailAddresses, ipAddresses, URIs, errors.New("One of more of the provided SANs is not properly formatted")
		}
		switch strings.Split(altName, ":")[0] {
		case "IP":
			tempIP := net.ParseIP(strings.Split(altName, ":")[1])
			if tempIP == nil {
				return dnsNames, emailAddresses, ipAddresses, URIs, errors.New("An invalid IP address was present in the request SAN")
			}
			ipAddresses = append(ipAddresses, tempIP)
		case "DNS":
		case "email":
		case "URI":
		default:
			return dnsNames, emailAddresses, ipAddresses, URIs, errors.New("One of more of the provided SANs is not properly formatted")
		}
	}

	return dnsNames, emailAddresses, ipAddresses, URIs, nil
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

// GetTemplate -------------------------------------------------------------------
// Returns an object containing the details associated with the template name passed
// to the method. Returns error if template is not found.
func GetTemplate(TemplateName string) (types.Template, error) {
	var template types.Template
	var err error

	return template, err
}

// GenSerialNum ------------------------------------------------------------------
// Generates a new serial number and validates it doesn't already exist in the certificate
// store
func GenSerialNum() (*big.Int, error) {
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

// GetCertFromDAP ----------------------------------------------------------------
// Finds matching certificate matching serial number in DAP and returns it; Sends appropriate
// error message as necessary
func GetCertFromDAP(serialNumber *big.Int) (x509.Certificate, error) {
	return x509.Certificate{}, errors.New("No certificate found matching serial number")
}

// ValidateKeyAlgoAndSize ------------------------------------------------------
func ValidateKeyAlgoAndSize(keyAlgo string, keySize string) error {
	switch keyAlgo {
	case "RSA":
		if _, err := strconv.Atoi(keySize); err != nil {
			return errors.New("Invalid key size for key algorithm RSA")
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

// GetCACert ------------------------------------------------------------------
func GetCACert() (x509.Certificate, error) {
	return x509.Certificate{}, nil
}

// GetTemplateFromDAP ----------------------------------------------------------
func GetTemplateFromDAP(templateName string) (types.Template, error) {
	return types.Template{}, nil
}

// CreateTemplateInDAP ---------------------------------------------------------
func CreateTemplateInDAP(newTemplate types.Template) error {
	return nil
}

// DeleteTemplateFromDAP --------------------------------------------------------
func DeleteTemplateFromDAP(newTemplate types.Template) error {
	return nil
}
