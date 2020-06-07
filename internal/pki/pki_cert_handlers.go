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
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// SignCertHandler -------------------------------------------------------------
func (p *Pki) SignCertHandler(w http.ResponseWriter, r *http.Request) {
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
	if err != nil {
		http.Error(w, "Unable to process request body data.  JSON Unmarshal returned error: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Extract the CSR from the request and process it to be converted to useful CertificateRequest object
	pemCSR, _ := pem.Decode([]byte(signReq.CSR))
	certReq, err := x509.ParseCertificateRequest(pemCSR.Bytes)
	if err != nil {
		http.Error(w, "The CSR provided in the request was not able to be successfully parsed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	template, serialNumber, ttl, sigAlgo, caCert, signingKey, err := p.PrepareCertificateParameters(signReq.TemplateName, signReq.TTL, p.Backend)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Setting subject data for template and CSR to validate that CSR is not out of bounds
	templateSubject, err := SetCertSubject(template.Subject, "")

	csrSubject := certReq.Subject
	csrSubject.CommonName = ""

	if templateSubject.String() != csrSubject.String() {
		http.Error(w, "The subject of the CSR does not match the allowed format in the requested template", http.StatusBadRequest)
		return
	}
	csrSubject.CommonName = signReq.CommonName

	// Retrieve the CSR extensions in order to parse out and validate the KeyUsages and ExtKeyUsages
	extKeyUsage := []x509.ExtKeyUsage{}
	var keyUsage x509.KeyUsage
	requestExtensions := certReq.Extensions
	for _, extension := range requestExtensions {
		if extension.Id.Equal([]int{2, 5, 29, 15}) {
			keyUsage, err = ValidateKeyUsageConstraints(extension.Value, template.KeyUsages)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
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

	// Still need to configure logic in new certificate for OCSPServer/IssuingCertificateURL/CRLDistributionPoints
	newCert := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csrSubject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Second * time.Duration(ttl)),
		SignatureAlgorithm:    sigAlgo,
		AuthorityKeyId:        caCert.SubjectKeyId,
		KeyUsage:              keyUsage,
		BasicConstraintsValid: false,
		IsCA:                  false,
	}

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
func (p *Pki) CreateCertHandler(w http.ResponseWriter, r *http.Request) {

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

	template, serialNumber, ttl, sigAlgo, caCert, signingKey, err := p.PrepareCertificateParameters(certReq.TemplateName, certReq.TTL, p.Backend)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract all the necessary data from the template to be used in generating the new
	// x509.Certificate object to be signed
	certSubject, err := SetCertSubject(template.Subject, certReq.CommonName)

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
		BasicConstraintsValid: false,
		IsCA:                  false,
	}

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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	derCert, err := x509.CreateCertificate(rand.Reader, &newCert, caCert, clientPubKey, signingKey)

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

	cert := types.CreateCertificateInDap{
		SerialNumber:   serialNumber.String(),
		Revoked:        false,
		ExpirationDate: time.Now().Add(time.Duration(time.Minute * time.Duration(ttl))).String(),
		Certificate:    base64.StdEncoding.EncodeToString(derCert),
	}
	p.Backend.CreateCertificate(cert)
	json.NewEncoder(w).Encode(response)

}

// GetCertHandler --------------------------------------------------------------------
func (p *Pki) GetCertHandler(w http.ResponseWriter, r *http.Request) {

	serialNumber := mux.Vars(r)["serialNumber"]

	// Convert the serial number into a format that is usable by the x509 library
	intSerialNumber, err := ConvertSerialOctetStringToInt(serialNumber)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	certificate, err := p.Backend.GetCertificate(intSerialNumber)
	if err != nil {
		http.Error(w, "Unable to retrieve certificate matching requested serial number", http.StatusNotFound)
		return
	}

	derCert, err := base64.StdEncoding.DecodeString(certificate)
	if err != nil {
		http.Error(w, "Unable to decode certificate returned from backend: "+err.Error(), http.StatusNotFound)
		return
	}

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
	response := types.PEMCertificate{
		Certificate: string(pemCert),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// ListCertsHandler ------------------------------------------------------------------
func (p *Pki) ListCertsHandler(w http.ResponseWriter, r *http.Request) {
	serialNumberList, err := p.Backend.ListCertificates()

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
func (p *Pki) RevokeCertHandler(w http.ResponseWriter, r *http.Request) {
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
	oldCRL, err := GetRevokedCertsFromDAP()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	revokedCertList = append(revokedCertList, oldCRL...)

	encodedSigningKey, err := p.Backend.GetSigningKey()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	decodedSigningKey, err := base64.StdEncoding.DecodeString(encodedSigningKey)
	signingKey, err := x509.ParsePKCS8PrivateKey(decodedSigningKey)
	if err != nil {
		if strings.Contains(err.Error(), "ParsePKCS1PrivateKey") {
			signingKey, err = x509.ParsePKCS1PrivateKey(decodedSigningKey)
			if err != nil {
				http.Error(w, "Unable to parse signing key from DAP: "+err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			http.Error(w, "Unable to parse signing key from DAP: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	encodedCACert, err := p.Backend.GetSigningCert()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	derCACert, err := base64.StdEncoding.DecodeString(encodedCACert)
	if err != nil {
		http.Error(w, "Unable to decode encoded CA certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}
	caCert, err := x509.ParseCertificate(derCACert)
	if err != nil {
		http.Error(w, "Unable to parse CA certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}
	newCRL, err := caCert.CreateCRL(rand.Reader, signingKey, revokedCertList, revokeTime, revokeTime.Add(time.Hour*12))
	if err != nil {
		http.Error(w, "Error while creating new CRL: "+err.Error(), http.StatusInternalServerError)
		return
	}

	p.Backend.WriteCRL(base64.StdEncoding.EncodeToString(newCRL))
}
