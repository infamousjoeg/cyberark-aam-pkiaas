package pki

import (
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
	"time"

	"github.com/gorilla/mux"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

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
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	clientPrivKey, clientPubKey, err := GenerateKeys(template.KeyAlgo, template.KeyBits)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var ttl int64
	serialNumber, err := GenerateSerialNumber()
	if certReq.TTL < template.MaxTTL {
		ttl = certReq.TTL
	} else {
		ttl = template.MaxTTL
	}

	caCertPEM, err := GetSigningCertFromDAP()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	blockCaCert, _ := pem.Decode([]byte(caCertPEM))
	derCaCert := blockCaCert.Bytes
	caCert, err := x509.ParseCertificate(derCaCert)
	signingKey, err := GetSigningKeyFromDAP()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
	derCert, err := x509.CreateCertificate(rand.Reader, &newCert, caCert, clientPubKey, signingKey)

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
	strSerialNumber, err := ConvertSerialIntToOctetString(serialNumber)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	response := types.CreateCertificateResponse{
		Certificate:   string(pemCert),
		PrivateKey:    string(pemPrivKey),
		CACert:        string(pemCA),
		SerialNumber:  strSerialNumber,
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
