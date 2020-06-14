package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// SignCertHandler -------------------------------------------------------------
// Handler method to read a CSR from HTTP request and generate a CA-signed certificate
// from it. Before being signed, the CSR's properties and extensions are compared
// against a template
func (p *Pki) SignCertHandler(w http.ResponseWriter, r *http.Request) {
	if !ValidateContentType(r.Header, "application/json") {
		http.Error(w, "CPKISG001: Invalid HTTP Content-Type header - expected application/json", http.StatusUnsupportedMediaType)
		return
	}

	// Ensure that the requesting entity can both authenticate to the PKI service, as well as
	// has authorization to access the Sign Certificate endpoint using the requested template
	authHeader := r.Header.Get("Authorization")
	err := p.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		http.Error(w, "CPKISG002: Invalid authentication from header - "+err.Error(), http.StatusUnauthorized)
		return
	}
	var signReq types.SignRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&signReq)
	if err != nil {
		http.Error(w, "CPKIRC003: Not able to decode request JSON data - "+err.Error(), http.StatusBadRequest)
		return
	}
	err = p.Backend.GetAccessControl().SignCertificate(authHeader, signReq.TemplateName)
	if err != nil {
		http.Error(w, "CPKISG004: Not authorized to sign certificate using "+signReq.TemplateName+" - "+err.Error(), http.StatusForbidden)
		return
	}

	// Extract the CSR from the request and process it to be converted to useful CertificateRequest object
	pemCSR, _ := pem.Decode([]byte(signReq.CSR))
	if pemCSR == nil {
		http.Error(w, "CPKISG005: No valid PEM block was found in request", http.StatusBadRequest)
	}
	certReq, err := x509.ParseCertificateRequest(pemCSR.Bytes)
	if err != nil {
		http.Error(w, "CPKISG006: Error parsing the certificate request - "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Retrieve data from the storage backend and set all necessary parameters required to sign the certifcate
	template, serialNumber, ttl, sigAlgo, caCert, signingKey, err := p.PrepareCertificateParameters(signReq.TemplateName, signReq.TTL, p.Backend)
	if err != nil {
		http.Error(w, "CPKISG007: Unable to set required parameters - "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Setting Subject data for template and CSR
	templateSubject, err := SetCertSubject(template.Subject, signReq.CommonName)
	if err != nil {
		http.Error(w, "CPKISG008: Unable to set certificate Subject fields - "+err.Error(), http.StatusInternalServerError)
		return
	}
	csrSubject := certReq.Subject
	csrSubject.CommonName = signReq.CommonName

	// Validate that the certificate request subject fields match those required by the template
	// TODO: Parameterize individual policies for each Subject field to specify whether they are optional matches or required
	fmt.Println(templateSubject.String())
	fmt.Println(csrSubject.String())
	if templateSubject.String() != csrSubject.String() {
		http.Error(w, "CPKISG009: CSR Subject does not match the Subject set in the template", http.StatusBadRequest)
		return
	}

	// Retrieve the CSR extensions in order to parse out and validate the KeyUsages and ExtKeyUsages
	// If the key usages are valid, set them to a x509.KeyUsage/x509.ExtendedKeyUsage object to be
	// passed into the new Certificate object
	extKeyUsage := []x509.ExtKeyUsage{}
	var keyUsage x509.KeyUsage
	requestExtensions := certReq.Extensions
	for _, extension := range requestExtensions {
		if extension.Id.Equal([]int{2, 5, 29, 15}) { // ASN.1 OID for key usages
			keyUsage, err = ValidateKeyUsageConstraints(extension.Value, template.KeyUsages)
			if err != nil {
				http.Error(w, "CPKISG010: Key usage validation failed - "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		if extension.Id.Equal([]int{2, 5, 29, 37}) { // ASN.1 OID for extended key usages
			extKeyUsage, err = ValidateExtKeyUsageConstraints(extension.Value, template.ExtKeyUsages)
			if err != nil {
				http.Error(w, "CPKISG011: Extended key usage validation failed - "+err.Error(), http.StatusBadRequest)
				return
			}
		}
	}

	// Validate that all the SANs from the HTTP request are either
	// explicitly permitted by the template or NOT explicitly denied
	// by the template
	err = ValidateSubjectAltNames(certReq.DNSNames, certReq.EmailAddresses, certReq.IPAddresses, certReq.URIs, template)
	if err != nil {
		http.Error(w, "CPKISG012: Subject Alternate Name validation failed - "+err.Error(), http.StatusBadRequest)
		return
	}

	// Still need to configure logic in new certificate for OCSPServer/IssuingCertificateURL/CRLDistributionPoints
	newCert := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csrSubject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Minute * time.Duration(ttl)),
		SignatureAlgorithm:    sigAlgo,
		AuthorityKeyId:        caCert.SubjectKeyId,
		KeyUsage:              keyUsage,
		BasicConstraintsValid: false,
		IsCA:                  false,
		OCSPServer:            ocspServer,
		IssuingCertificateURL: issuingCertificateURL,
		CRLDistributionPoints: crlDistributionPoints,
	}

	// Only add extended key usages and SAN fields if they exist
	if len(extKeyUsage) > 0 {
		newCert.ExtKeyUsage = extKeyUsage
	}
	if len(certReq.DNSNames) > 0 {
		newCert.DNSNames = certReq.DNSNames
	}
	if len(certReq.EmailAddresses) > 0 {
		newCert.EmailAddresses = certReq.EmailAddresses
	}
	if len(certReq.IPAddresses) > 0 {
		newCert.IPAddresses = certReq.IPAddresses
	}
	if len(certReq.URIs) > 0 {
		newCert.URIs = certReq.URIs
	}

	derCert, err := x509.CreateCertificate(rand.Reader, &newCert, caCert, certReq.PublicKey, signingKey)
	if err != nil {
		http.Error(w, "CPKISG013: Error while creating certificate - "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert the certifcate objects into PEMs to be returned as strings
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
	pemCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	w.Header().Set("Content-Type", "application/json")
	strSerialNumber, err := ConvertSerialIntToOctetString(serialNumber)
	if err != nil {
		http.Error(w, "CPKISG014: Error converting serial nubmer to octet string: - "+err.Error(), http.StatusInternalServerError)
		return
	}
	response := types.CreateCertificateResponse{
		Certificate:   string(pemCert),
		CACert:        string(pemCA),
		SerialNumber:  strSerialNumber,
		LeaseDuration: ttl,
	}

	// Object for the data to be written to the storage backend
	cert := types.CreateCertificateData{
		SerialNumber:   serialNumber.String(),
		Revoked:        false,
		ExpirationDate: time.Now().Add(time.Duration(time.Minute * time.Duration(ttl))).String(),
		Certificate:    base64.StdEncoding.EncodeToString(derCert),
	}
	err = p.Backend.CreateCertificate(cert)
	if err != nil {
		http.Error(w, "CPKISG015: Error writing certificate to storage backend - "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, "CPKICR016: Error writing HTTP response - "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// CreateCertHandler -----------------------------------------------------------
// Handler method used to build a new certificate with the provided common name
// based upon the provided template
func (p *Pki) CreateCertHandler(w http.ResponseWriter, r *http.Request) {
	if !ValidateContentType(r.Header, "application/json") {
		http.Error(w, "CPKICC001: Invalid HTTP Content-Type header - expected application/json", http.StatusUnsupportedMediaType)
		return
	}

	// Ensure that the requesting entity can both authenticate to the PKI service, as well as
	// has authorization to access the Create Certificate endpoint using the requested template
	authHeader := r.Header.Get("Authorization")
	err := p.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		http.Error(w, "CPKICC002: Invalid authentication from header - "+err.Error(), http.StatusUnauthorized)
		return
	}
	var certReq types.CreateCertReq
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&certReq)
	if err != nil {
		http.Error(w, "CPKIRC003: Not able to decode request JSON data - "+err.Error(), http.StatusBadRequest)
		return
	}

	err = p.Backend.GetAccessControl().CreateCertificate(authHeader, certReq.TemplateName)
	if err != nil {
		http.Error(w, "CPKICC004: Not authorized to create certificate with template "+certReq.TemplateName+" - "+err.Error(), http.StatusForbidden)
		return
	}

	// Retrieve data from the storage backend and set all necessary parameters required to sign the certifcate
	template, serialNumber, ttl, sigAlgo, caCert, signingKey, err := p.PrepareCertificateParameters(certReq.TemplateName, certReq.TTL, p.Backend)
	if err != nil {
		http.Error(w, "CPKICC005: Unable to set required parameters - "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Create a pkix.Name object from the Subject data in the template to
	// be used in the new Certificate object
	certSubject, err := SetCertSubject(template.Subject, certReq.CommonName)
	if err != nil {
		http.Error(w, "CPKICC006: Unable to set certificate Subject fields - "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Process the key usages stored in the requested template and return
	// them in a x509.KeyUsage object
	keyUsage, err := ProcessKeyUsages(template.KeyUsages)
	if err != nil {
		http.Error(w, "CPKICC007: Error processing key usages - "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Process the extended key usages stored in the requested template and return
	// them in a x509.ExtendedKeyUsage object
	extKeyUsage, err := ProcessExtKeyUsages(template.ExtKeyUsages)
	if err != nil {
		http.Error(w, "CPKICC008: Error processing extended key usages - "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Process the request's Subject Alternate Name fields into arrays specific to each
	// type of SAN, then validate that the requested SANs are permitted/not excluded by
	// the template
	dnsNames, emailAddresses, ipAddresses, URIs, err := ProcessSubjectAltNames(certReq.AltNames)
	if err != nil {
		http.Error(w, "CPKICC009: Error processing Subject Alternate Names - "+err.Error(), http.StatusBadRequest)
		return
	}
	err = ValidateSubjectAltNames(dnsNames, emailAddresses, ipAddresses, URIs, template)
	if err != nil {
		http.Error(w, "CPKICC010: Subject Alternate Name validation failed - "+err.Error(), http.StatusBadRequest)
		return
	}

	newCert := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               certSubject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Minute * time.Duration(ttl)),
		SignatureAlgorithm:    sigAlgo,
		AuthorityKeyId:        caCert.SubjectKeyId,
		KeyUsage:              keyUsage,
		BasicConstraintsValid: false,
		IsCA:                  false,
		OCSPServer:            ocspServer,
		IssuingCertificateURL: issuingCertificateURL,
		CRLDistributionPoints: crlDistributionPoints,
	}

	// Only add extended key usages and SAN fields if they exist
	if len(extKeyUsage) > 0 {
		newCert.ExtKeyUsage = extKeyUsage
	}
	if len(dnsNames) > 0 {
		newCert.DNSNames = dnsNames
	}
	if len(emailAddresses) > 0 {
		newCert.EmailAddresses = emailAddresses
	}
	if len(ipAddresses) > 0 {
		newCert.IPAddresses = ipAddresses
	}
	if len(URIs) > 0 {
		newCert.URIs = URIs
	}

	clientPrivKey, clientPubKey, err := GenerateKeys(template.KeyAlgo, template.KeyBits)
	if err != nil {
		http.Error(w, "CPKICC011: Error generating keys for certificate - "+err.Error(), http.StatusInternalServerError)
		return
	}

	derCert, err := x509.CreateCertificate(rand.Reader, &newCert, caCert, clientPubKey, signingKey)
	if err != nil {
		http.Error(w, "CPKICC012: Error while creating certificate - "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert the certifcate objects into PEMs to be returned as strings
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
	pemCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	var pemPrivKey []byte

	// Generate the appropriate PEM type for the created private key
	switch template.KeyAlgo {
	case "RSA":
		pemPrivKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientPrivKey.(*rsa.PrivateKey))})
	case "ECDSA":
		ecKey, err := x509.MarshalECPrivateKey(clientPrivKey.(*ecdsa.PrivateKey))
		if err != nil {
			http.Error(w, "CPKICC013: Unable to marshal new ECDSA private key - "+err.Error(), http.StatusInternalServerError)
			return
		}
		pemPrivKey = pem.EncodeToMemory(&pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: ecKey})
	case "ED25519":
		pemPrivKey = pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: clientPrivKey.(ed25519.PrivateKey)})
	}
	w.Header().Set("Content-Type", "application/json")
	strSerialNumber, err := ConvertSerialIntToOctetString(serialNumber)
	if err != nil {
		http.Error(w, "CPKICC014: Error converting serial nubmer to octet string: - "+err.Error(), http.StatusInternalServerError)
	}

	// Object for HTTP response body to be returned
	response := types.CreateCertificateResponse{
		Certificate:   string(pemCert),
		PrivateKey:    string(pemPrivKey),
		CACert:        string(pemCA),
		SerialNumber:  strSerialNumber,
		LeaseDuration: ttl,
	}
	// Object for the data to be written to the storage backend
	cert := types.CreateCertificateData{
		SerialNumber:   serialNumber.String(),
		Revoked:        false,
		ExpirationDate: time.Now().Add(time.Duration(time.Minute * time.Duration(ttl))).String(),
		Certificate:    base64.StdEncoding.EncodeToString(derCert),
	}
	err = p.Backend.CreateCertificate(cert)
	if err != nil {
		http.Error(w, "CPKICC015: Error writing certificate to storage backend - "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, "CPKICC016: Error writing HTTP response - "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// GetCertHandler --------------------------------------------------------------------
func (p *Pki) GetCertHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	serialNumber := mux.Vars(r)["serialNumber"]

	// Ensure that the requesting entity can both authenticate to the PKI service, but there
	// is no need for an authorization check as all authenticated entities will be allowed
	// to retrieve public certificate data
	err := p.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		http.Error(w, "CPKICE001: Invalid authentication from header - "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Convert the serial number into a format that is usable by the x509 library
	intSerialNumber, err := ConvertSerialOctetStringToInt(serialNumber)
	if err != nil {
		http.Error(w, "CPKICE002: Error while converting serial number octet string - "+err.Error(), http.StatusBadRequest)
		return
	}

	// Retrieve base64 encoded certificate from backend, then decode and convert to PEM
	certificate, err := p.Backend.GetCertificate(intSerialNumber)
	if err != nil {
		http.Error(w, "CPKICE003: Error retrieving certificate from storage backend - "+err.Error(), http.StatusNotFound)
		return
	}
	derCert, err := base64.StdEncoding.DecodeString(certificate)
	if err != nil {
		http.Error(w, "CPKICE004: Error decoding returned certificate - "+err.Error(), http.StatusNotFound)
		return
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
	response := types.PEMCertificate{
		Certificate: string(pemCert),
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, "CPKICE005: Error writing HTTP response - "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// ListCertsHandler ------------------------------------------------------------------
// Handler method used to retrieve the serial number of all certificates currently
// in the backend storage repository and return them
func (p *Pki) ListCertsHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")

	// Ensure that the requesting entity can both authenticate to the PKI service, but there
	// is no need for an authorization check as all authenticated entities will be allowed
	// to retrieve public certificate data
	err := p.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		http.Error(w, "CPKILC001: Invalid authentication from header - "+err.Error(), http.StatusUnauthorized)
		return
	}

	serialNumberList, err := p.Backend.ListCertificates()
	if err != nil {
		http.Error(w, "CPKILC002: Error retrieving certificate list from storage backend - "+err.Error(), http.StatusInternalServerError)
		return
	}

	retSerialNumbers := []string{}
	for _, serialNumber := range serialNumberList {
		strSerialNumber, err := ConvertSerialIntToOctetString(serialNumber)
		if err != nil {
			http.Error(w, "CPKILC003: Error converting serial number to octet string - "+err.Error(), http.StatusInternalServerError)
			return
		}
		retSerialNumbers = append(retSerialNumbers, strSerialNumber)
	}

	response := types.CertificateListResponse{
		Certificates: retSerialNumbers,
	}
	w.Header().Set("Content-Type", "application/json")

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, "CPKILC004: Error writing HTTP response - "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// RevokeCertHandler -----------------------------------------------------------------
// Handler method that updates to revoke a certificate for a specified, but optional,
// reason code.  Updates the certificate object in the storage backend as well as generates
// a new CRL
func (p *Pki) RevokeCertHandler(w http.ResponseWriter, r *http.Request) {
	if !ValidateContentType(r.Header, "application/json") {
		http.Error(w, "CPKIRC001: Invalid HTTP Content-Type header - expected application/json", http.StatusUnsupportedMediaType)
		return
	}

	// Ensure that the requesting entity can both authenticate to the PKI service, as well as
	// has authorization to access the Revoke Certificate endpoint for the specified serial number
	authHeader := r.Header.Get("Authorization")
	err := p.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		http.Error(w, "CPKIRC002: Invalid authentication from header - "+err.Error(), http.StatusUnauthorized)
		return
	}
	var crlReq = types.RevokeRequest{}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&crlReq)
	if err != nil {
		http.Error(w, "CPKIRC003: Not able to decode request JSON data - "+err.Error(), http.StatusBadRequest)
		return
	}
	err = p.Backend.GetAccessControl().RevokeCertificate(authHeader, crlReq.SerialNumber)
	if err != nil {
		http.Error(w, "CPKIRC004: Not authorized to revoke certificate with serial number "+crlReq.SerialNumber+" - "+err.Error(), http.StatusForbidden)
		return
	}

	// Capture the numeric reason code, certificate revocation time, and serial number
	// used to generate the revocation entry
	reasonCode := -1
	if crlReq.Reason != "" {
		reasonCode, err = ReturnReasonCode(crlReq.Reason)
		if err != nil {
			http.Error(w, "CPKIRC005: Error parsing revocation reason - "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	revokeTime := time.Now()
	intSerialNum, err := ConvertSerialOctetStringToInt(crlReq.SerialNumber)
	if err != nil {
		http.Error(w, "CPKIRC006: Error converting serial number to integer value"+err.Error(), http.StatusBadRequest)
		return
	}

	err = p.Backend.RevokeCertificate(intSerialNum, reasonCode, revokeTime)
	if err != nil {
		http.Error(w, "CPKIRC007: Certificate revocation failed on storage backend - "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Loop through all revoke certificates from the storage backend (including that being revoked by this method call)
	// and generate a pkix.RevokedCertificates array to be used for the generation of a new
	// CRL
	revokedCertificates, err := p.Backend.GetRevokedCerts()
	if err != nil {
		http.Error(w, "CPKIRC008: Error retrieving revoked certificates list from storage backend - "+err.Error(), http.StatusInternalServerError)
		return
	}
	revokedCertList := []pkix.RevokedCertificate{}
	for _, revokedCertificate := range revokedCertificates {
		crlExtensions := []pkix.Extension{}
		if revokedCertificate.ReasonCode > 0 {
			reasonExtension := pkix.Extension{
				Id:    asn1.ObjectIdentifier{2, 5, 29, 21}, // ASN.1 OID for CRL reason code
				Value: []byte(strconv.Itoa(reasonCode)),
			}
			crlExtensions = append(crlExtensions, reasonExtension)
		}
		intSerialNum := new(big.Int)
		intSerialNum, success := intSerialNum.SetString(revokedCertificate.SerialNumber, 10)
		if !success {
			http.Error(w, "CPKIRC009: Error converting serial number integer from string", http.StatusInternalServerError)
			return
		}
		crlEntry := pkix.RevokedCertificate{
			SerialNumber:   intSerialNum,
			RevocationTime: revokedCertificate.RevocationDate,
			Extensions:     crlExtensions,
		}
		revokedCertList = append(revokedCertList, crlEntry)
	}

	// Retrieve the base64 encoded signing key from storage backend and decode it
	encodedSigningKey, err := p.Backend.GetSigningKey()
	if err != nil {
		http.Error(w, "CPKIRC010: Error retrieving signing key from storage backend - "+err.Error(), http.StatusInternalServerError)
		return
	}
	decodedSigningKey, err := base64.StdEncoding.DecodeString(encodedSigningKey)

	// Try to parse the private key using PKCS8, and if it fails attempt to use the recommended
	// parsing format from the PKCS8 error
	signingKey, err := x509.ParsePKCS8PrivateKey(decodedSigningKey)
	if err != nil {
		if strings.Contains(err.Error(), "ParsePKCS1PrivateKey") {
			signingKey, err = x509.ParsePKCS1PrivateKey(decodedSigningKey)
			if err != nil {
				http.Error(w, "CPKIRC011: Error parsing signing key - "+err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			http.Error(w, "CPKIRC011: Error parsing signing key - "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Retrieve the base64 encoded signing key from storage backend and decode it
	encodedCACert, err := p.Backend.GetSigningCert()
	if err != nil {
		http.Error(w, "CPKIRC012: Error retrieving CA certificate from storage backend: "+err.Error(), http.StatusInternalServerError)
		return
	}
	derCACert, err := base64.StdEncoding.DecodeString(encodedCACert)
	if err != nil {
		http.Error(w, "CPKIRC013: Unable to decode encoded CA certificate - "+err.Error(), http.StatusInternalServerError)
		return
	}
	caCert, err := x509.ParseCertificate(derCACert)
	if err != nil {
		http.Error(w, "CPKIRC014: Unable to parse CA certificate - "+err.Error(), http.StatusInternalServerError)
		return
	}
	newCRL, err := caCert.CreateCRL(rand.Reader, signingKey, revokedCertList, revokeTime, revokeTime.Add(time.Hour*12))
	if err != nil {
		http.Error(w, "CPKI015: Error while creating new CRL - "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = p.Backend.WriteCRL(base64.StdEncoding.EncodeToString(newCRL))
	if err != nil {
		http.Error(w, "CPKI016: Error writing new CRL to storage backend - "+err.Error(), http.StatusInternalServerError)
		return
	}
}

/********************************************
TODO:
func HoldCertHandler(w http.ResponseWriter, r *http.Request) {

}
******************************************/

/********************************************
TODO:
func ReleaseCertHandler(w http.ResponseWriter, r *http.Request) {

}
******************************************/
