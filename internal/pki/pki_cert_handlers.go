package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
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

	// Extract the CSR from the request and process it to be converted to useful CertificateRequest object
	pemCSR, _ := pem.Decode([]byte(signReq.CSR))
	certReq, err := x509.ParseCertificateRequest(pemCSR.Bytes)
	if err != nil {
		http.Error(w, "The CSR provided in the request was not able to be successfully parsed", http.StatusInternalServerError)
		return
	}
	template, err := GetTemplateFromDAP(signReq.TemplateName)
	if err != nil {
		http.Error(w, "Unable to retrieve template "+signReq.TemplateName+" sent in request", http.StatusBadRequest)
		return
	}

	// Setting subject data for template and CSR to validate that CSR is not out of bounds
	templateSubject := pkix.Name{
		Country:            []string{template.Country},
		Organization:       []string{template.Organization},
		OrganizationalUnit: []string{template.OrgUnit},
		Locality:           []string{template.Locality},
		Province:           []string{template.Province},
		StreetAddress:      []string{template.Address},
		PostalCode:         []string{template.PostalCode},
	}

	csrSubject := pkix.Name{
		Country:            certReq.Subject.Country,
		Organization:       certReq.Subject.Organization,
		OrganizationalUnit: certReq.Subject.OrganizationalUnit,
		Locality:           certReq.Subject.Locality,
		Province:           certReq.Subject.Province,
		StreetAddress:      certReq.Subject.StreetAddress,
		PostalCode:         certReq.Subject.PostalCode,
	}

	if templateSubject.String() != csrSubject.String() {
		http.Error(w, "The subject of the CSR does not match the allowed format in the requested template", http.StatusBadRequest)
		return
	}
	csrSubject.CommonName = signReq.CommonName

	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Retrieve the CSR extensions in order to parse out and validate the KeyUsages and ExtKeyUsages
	extKeyUsage := []x509.ExtKeyUsage{}
	var keyUsage x509.KeyUsage
	requestExtensions := certReq.Extensions
	for _, extension := range requestExtensions {
		if extension.Id.Equal([]int{2, 5, 29, 15}) {
			keyUsage, err = ValidateKeyUsageConstraints(extension.Value, template.KeyUsages)
			if err != nil {
				http.Error(w, err.Error()+"The CSR has requested key usages that are not permitted in the given template", http.StatusBadRequest)
				return
			}
		}
		if extension.Id.Equal([]int{2, 5, 29, 37}) {
			extKeyUsage, err = ValidateExtKeyUsageConstraints(extension.Value, template.ExtKeyUsages)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
	}

	err = ValidateSubjectAltNames(certReq.DNSNames, certReq.EmailAddresses, certReq.IPAddresses, certReq.URIs, template)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Set the TTL value to either that which was request or the max TTL allowed by the template
	// in the event that the requested TTL was greater
	var ttl int64
	if signReq.TTL < template.MaxTTL {
		ttl = signReq.TTL
	} else {
		ttl = template.MaxTTL
	}

	// Retrieve the intermediate CA certificate from DAP and go through the necessary steps
	// to convert it from a PEM-string to a usable x509.Certificate object
	caCertPEM, err := GetSigningCertFromDAP()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	blockCaCert, _ := pem.Decode([]byte(caCertPEM))
	derCaCert := blockCaCert.Bytes
	caCert, err := x509.ParseCertificate(derCaCert)

	// Retrieve the signing key from DAP and calculate the signature algorithm for use in the
	// certificate generation
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

	// Still need to configure logic in new certificate for OCSPServer/IssuingCertificateURL/CRLDistributionPoints
	newCert := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csrSubject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Second * time.Duration(ttl)),
		SignatureAlgorithm:    sigAlgo,
		AuthorityKeyId:        caCert.SubjectKeyId,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: false,
		IsCA:                  false,
		DNSNames:              certReq.DNSNames,
		EmailAddresses:        certReq.EmailAddresses,
		IPAddresses:           certReq.IPAddresses,
		URIs:                  certReq.URIs,
	}
	derCert, err := x509.CreateCertificate(rand.Reader, &newCert, caCert, certReq.PublicKey, signingKey)

	// Convert the certifcate objects into PEMs to be returned as strings
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
	pemCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.RawTBSCertificate})

	w.Header().Set("Content-Type", "application/json")
	strSerialNumber, err := ConvertSerialIntToOctetString(serialNumber)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	response := types.CreateCertificateResponse{
		Certificate:   string(pemCert),
		CACert:        string(pemCA),
		SerialNumber:  strSerialNumber,
		LeaseDuration: ttl,
	}

	json.NewEncoder(w).Encode(response)
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

	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set the TTL value to either that which was request or the max TTL allowed by the template
	// in the event that the requested TTL was greater
	var ttl int64
	if certReq.TTL < template.MaxTTL {
		ttl = certReq.TTL
	} else {
		ttl = template.MaxTTL
	}

	// Retrieve the intermediate CA certificate from DAP and go through the necessary steps
	// to convert it from a PEM-string to a usable x509.Certificate object
	caCertPEM, err := GetSigningCertFromDAP()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	blockCaCert, _ := pem.Decode([]byte(caCertPEM))
	derCaCert := blockCaCert.Bytes
	caCert, err := x509.ParseCertificate(derCaCert)

	// Retrieve the signing key from DAP and calculate the signature algorithm for use in the
	// certificate generation
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

	// Extract all the necessary data from the template to be used in generating the new
	// x509.Certificate object to be signed
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
	dnsNames, emailAddresses, ipAddresses, URIs, err := ProcessSubjectAltNames(certReq.AltNames)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err = ValidateSubjectAltNames(dnsNames, emailAddresses, ipAddresses, URIs, template)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Still need to configure logic in new certificate for OCSPServer/IssuingCertificateURL/CRLDistributionPoints
	newCert := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               certSubject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Second * time.Duration(ttl)),
		SignatureAlgorithm:    sigAlgo,
		AuthorityKeyId:        caCert.SubjectKeyId,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: false,
		IsCA:                  false,
		DNSNames:              dnsNames,
		EmailAddresses:        emailAddresses,
		IPAddresses:           ipAddresses,
		URIs:                  URIs,
	}
	derCert, err := x509.CreateCertificate(rand.Reader, &newCert, caCert, clientPubKey, signingKey)

	// Convert the certifcate objects into PEMs to be returned as strings
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
	pemCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.RawTBSCertificate})
	var pemPrivKey []byte

	// Generate the appropriate PEM type for the created private key
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

	// Convert the serial number into a format that is usable by the x509 library
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

	// This will likely need to change to just return the `certificate` variable, as I believe it will
	// be stored in DAP as a PEM-string already
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
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}
	if !ValidateContentType(r.Header, "application/json") {
		http.Error(w, "Invalid content type: expected application/json", http.StatusUnsupportedMediaType)
		return
	}

	var crlReq = types.RevokeRequest{}

	err = json.Unmarshal(reqBody, &crlReq)
	if err != nil {
		http.Error(w, "Unable to process request body data.  JSON Unmarshal returned error: "+err.Error(), http.StatusBadRequest)
		return
	}
	reasonCode := -1
	if crlReq.Reason != "" {
		reasonCode, err = ReturnReasonCode(crlReq.Reason)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	crlExtensions := []pkix.Extension{}
	if reasonCode > 0 {
		reasonExtension := pkix.Extension{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 21},
			Value: []byte(strconv.Itoa(reasonCode)),
		}
		crlExtensions = append(crlExtensions, reasonExtension)
	}

	revokeTime := time.Now()
	intSerialNum, err := ConvertSerialOctetStringToInt(crlReq.SerialNumber)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	revokedCert := pkix.RevokedCertificate{
		SerialNumber:   intSerialNum,
		RevocationTime: revokeTime,
		Extensions:     crlExtensions,
	}

	revokedCertList := []pkix.RevokedCertificate{revokedCert}

	revokedCertList = append(revokedCertList, GetRevokedCertsFromDAP()...)
	RevokeCertInDAP(intSerialNum, reasonCode, revokeTime)

	signingKey, err := GetSigningKeyFromDAP()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	caCertPEM, err := GetSigningCertFromDAP()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	blockCaCert, _ := pem.Decode([]byte(caCertPEM))
	derCaCert := blockCaCert.Bytes
	caCert, err := x509.ParseCertificate(derCaCert)
	newCRL, err := caCert.CreateCRL(rand.Reader, signingKey, revokedCertList, revokeTime, revokeTime.Add(time.Hour*12))

	pemCRL := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: newCRL})

	WriteCRLToDAP(string(pemCRL))
}
