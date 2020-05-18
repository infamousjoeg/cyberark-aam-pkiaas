package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"time"

	"github.com/gorilla/mux"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// GenerateIntermediateCSRHandler ------------------------------------------
func GenerateIntermediateCSRHandler(w http.ResponseWriter, r *http.Request) {
	reqBody, err := ioutil.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}

	if !ValidateContentType(r.Header, "application/json") {
		http.Error(w, "Invalid content type: expected application/json", http.StatusUnsupportedMediaType)
		return
	}

	var intermediateRequest types.IntermediateRequest
	err = json.Unmarshal(reqBody, &intermediateRequest)
}

// SetIntermediateCertHandler ----------------------------------------------
func SetIntermediateCertHandler(w http.ResponseWriter, r *http.Request) {
	reqBody, err := ioutil.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}

	if !ValidateContentType(r.Header, "application/json") {
		http.Error(w, "Invalid content type: expected application/json", http.StatusUnsupportedMediaType)
		return
	}
	var signedCert types.PEMCertificate
	err = json.Unmarshal(reqBody, &signedCert)
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

	var newTemplate types.Template
	err = json.Unmarshal(reqBody, &newTemplate)
	if err != nil {
		http.Error(w, "Unable to process request body data.  JSON Unmarshal returned error: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Check for mandatory fields

	err = ValidateKeyAlgoAndSize(newTemplate.KeyAlgo, newTemplate.KeyBits)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Validate and sanitize Subject data

	_, err = ProcessKeyUsages(newTemplate.KeyUsages)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, err = ProcessExtKeyUsages(newTemplate.ExtKeyUsages)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate permitted/excluded data
	_, err = ProcessPolicyIdentifiers(newTemplate.PolicyIdentifiers)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
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

	oldTemplate, err := GetTemplateFromDAP(newTemplate.TemplateName)
	if err != nil {
		http.Error(w, "The requested template "+newTemplate.TemplateName+" cannot be located", http.StatusBadRequest)
		return
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
	err = DeleteTemplateFromDAP(newTemplate.TemplateName)

}

// DeleteTemplateHandler -------------------------------------------------------
func DeleteTemplateHandler(w http.ResponseWriter, r *http.Request) {
	templateName := mux.Vars(r)["templateName"]
	err := DeleteTemplateFromDAP(templateName)
	if err != nil {
		http.Error(w, "Unable to delete requested template", http.StatusInternalServerError)
		return
	}
}

// GetTemplateHandler ----------------------------------------------------------
func GetTemplateHandler(w http.ResponseWriter, r *http.Request) {
	template, err := GetTemplateFromDAP(mux.Vars(r)["templateName"])

	if err != nil {
		http.Error(w, "Unable to retrieve requested template", http.StatusBadRequest)
		return
	}
	respTemplate, err := json.Marshal(template)

	if err != nil {
		http.Error(w, "The requested template was unable to be successfully processed into a response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(respTemplate)
}

// ListTemplatesHandler ---------------------------------------------------------
func ListTemplatesHandler(w http.ResponseWriter, r *http.Request) {
	templates, err := GetAllTemplatesFromDAP()

	if err != nil {
		http.Error(w, "Failed to retrieve a list of templates", http.StatusBadRequest)
		return
	}
	respTemplates, err := json.Marshal(templates)
	if err != nil {
		http.Error(w, "The server was unable to process the template list into an appropriate response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(respTemplates)
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
	template, err := GetTemplateFromDAP(certReq.TemplateName)

	clientPrivKey, clientPubKey, err := GenerateKeys(template.KeyAlgo, template.KeyBits)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var ttl int64
	serialNumber, err := GenSerialNum()
	if certReq.TTL < template.MaxTTL {
		ttl = certReq.TTL
	} else {
		ttl = template.MaxTTL
	}

	caCert, err := GetCACertFromDAP()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
		return
	}

	certSubject, err := SetCertSubject(template, certReq.CommonName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	keyUsage, err := ProcessKeyUsages(template.KeyUsages)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	extKeyUsage, err := ProcessExtKeyUsages(template.ExtKeyUsages)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	newCert := x509.Certificate{
		SerialNumber:       serialNumber,
		Subject:            certSubject,
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
		ecKey, err := x509.MarshalECPrivateKey(clientPrivKey.(*ecdsa.PrivateKey))
		if err != nil {
			http.Error(w, "Unable to successfully marshal new ECDSA key into PEM format for return", http.StatusInternalServerError)
			return
		}
		pemPrivKey = pem.EncodeToMemory(&pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: ecKey})
	case "ED25519":
		pemPrivKey = pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: clientPrivKey.(ed25519.PrivateKey)})
	}
	w.Header().Set("Content-Type", "application/json")
	response := types.CreateCertificateResponse{
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

	serialNumber := mux.Vars(r)["serialNumber"]

	intSerialNumber, err := ConvertSerialOctetStringToInt(serialNumber)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	certificate, err := GetCertFromDAP(intSerialNumber)

	if err != nil {
		http.Error(w, "Unable to retrieve certificate matching requested serial number", http.StatusNotFound)
		return
	}

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.RawTBSCertificate})
	response := types.PEMCertificate{
		Certificate: string(pemCert),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// ListCertsHandler ------------------------------------------------------------------
func ListCertsHandler(w http.ResponseWriter, r *http.Request) {
	serialNumberList, err := GetAllCertsFromDAP()

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	retSerialNumbers := []string{}
	for _, serialNumber := range serialNumberList {
		strSerialNumber, err := ConvertSerialIntToOctetString(serialNumber)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		retSerialNumbers = append(retSerialNumbers, strSerialNumber)
	}

	response := types.CertificateListResponse{
		Certificates: retSerialNumbers,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// RevokeCertHandler -----------------------------------------------------------------
func RevokeCertHandler(w http.ResponseWriter, r *http.Request) {

}

// GetCAHandler ----------------------------------------------------------------------
func GetCAHandler(w http.ResponseWriter, r *http.Request) {

}

// GetCAChainHandler -----------------------------------------------------------------
func GetCAChainHandler(w http.ResponseWriter, r *http.Request) {

}
