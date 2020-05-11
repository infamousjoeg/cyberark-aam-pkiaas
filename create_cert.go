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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"reflect"
	"strconv"
	"time"

	"github.com/golang/gddo/httputil/header"
)

// CreateCertReq ---------------------------------------------------------------
// Structure representing the HTTP request POSTed to the CreateCert API endpoint
type CreateCertReq struct {
	TemplateName string `json:"Template Name"`
	CommonName   string `json:"Common Name"`
	EmailAddress string `json:"Email Address"`
	TTL          int64
	Format       string
}

// Template -------------------------------------------------------------------
// Structure that represents a certificate request template
type Template struct {
	TemplateName      string
	KeyAlgo           string
	KeyBits           string
	MaxTTL            int64
	Organization      string
	OrgUnit           string
	Country           string
	Locality          string
	Province          string
	Address           string
	PostalCode        string
	AltNames          []string
	KeyUsages         []string
	ExtKeyUsages      []string
	MaxPathLength     string
	PermDNSDomains    []string
	ExclDNSDomains    []string
	PermIPRanges      []string
	ExclIPRanges      []string
	PermittedEmails   []string
	ExclEmails        []string
	PermURIDomains    []string
	ExclURIDomains    []string
	PolicyIdentifiers []string
}

type CertificateResponse struct {
	Certificate   []byte           `json:"certificate"`
	PrivateKey    []byte           `json: "private key"`
	CACert        x509.Certificate `json: "CA certificate"`
	SerialNumber  *big.Int         `json: "serial number"`
	LeaseDuration int64            `json: "lease duration"`
}

type SignRequest struct {
	CSR          string
	CommonName   string
	TTL          int64
	ReturnFormat string
}

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

	var newTemplate Template
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
	// Validate SAN objects
	// Validate key usage
	// Validate extended key usage
	// Validate permitted/excluded data
	// Validate policy identifiers

	// CreateTemplateInDAP(newTemplate)
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

	var newTemplate Template
	err = json.Unmarshal(reqBody, &newTemplate)
	if err != nil {
		http.Error(w, "Unable to process request body data.  JSON Unmarshal returned error: "+err.Error(), http.StatusBadRequest)
		return
	}

	//	oldTemplate, err := GetTemplateFromDAP(newTemplate.TemplateName)
	oldTemplate := Template{}
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

}

// GetTemplateHandler ----------------------------------------------------------
func GetTemplateHandler(w http.ResponseWriter, r *http.Request) {
	template, err := GetTemplateFromDAP(r.URL.Query()["TemplateName"])

	if err != nil {
		http.Error(w, "Unable to retrieve requested template", http.StatusBadRequest)
	}
}

// ListTemplatesHandler ---------------------------------------------------------
func ListTemplatesHandler(w http.ResponseWriter, r *http.Request) {
	templates, err := GetAllTemplatesFromDAP()

	if err != nil {
		http.Error(w, "Failed to retrieve a list of templates")
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
	var signReq SignRequest
	err = json.Unmarshal(reqBody, &signReq)
	certReq, err := x509.ParseCertificateRequest([]byte(signReq.CSR))
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
	var certReq CreateCertReq
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

	//	var keyUsage x509.KeyUsage
	//	first := true

	//	for usage := range template.KeyUsages {

	//	}

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
		//		SubjectKeyId: sha1HashOfPublicKey bit string
	}
	/*
	   CERTIFICATE PEM BLOCK
	   EXPIRATION DATE
	   SERIAL NUMBER
	   REVOKATION STATUS


	   []string, err := ConjurCertList()
	   { "certs": ["serial#1", "serial#2", "etc"]}

	*/
	derCert, err := x509.CreateCertificate(rand.Reader, &newCert, &caCert, clientPubKey, signingKey)

	// Update CRL Code Block

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
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
	response := CertificateResponse{
		Certificate:   pemCert,
		PrivateKey:    pemPrivKey,
		CACert:        caCert,
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

// GetTemplate -------------------------------------------------------------------
// Returns an object containing the details associated with the template name passed
// to the method. Returns error if template is not found.
func GetTemplate(TemplateName string) (Template, error) {
	var template Template
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
