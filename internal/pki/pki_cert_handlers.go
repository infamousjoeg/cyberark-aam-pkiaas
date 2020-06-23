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
	"encoding/pem"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/httperror"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// SignCert -----------------
func SignCert(signReq types.SignRequest, backend backend.Storage) (types.CreateCertificateResponse, httperror.HTTPError) {
	// Extract the CSR from the request and process it to be converted to useful CertificateRequest object
	pemCSR, _ := pem.Decode([]byte(signReq.CSR))
	if pemCSR == nil {
		return types.CreateCertificateResponse{}, httperror.InvalidPEM()
	}
	certReq, err := x509.ParseCertificateRequest(pemCSR.Bytes)
	if err != nil {
		return types.CreateCertificateResponse{}, httperror.ParseCSRError(err.Error())
	}

	// Retrieve data from the storage backend and set all necessary parameters required to sign the certifcate
	template, serialNumber, ttl, sigAlgo, caCert, signingKey, err := PrepareCertificateParameters(signReq.TemplateName, signReq.TTL, backend)
	if err != nil {
		return types.CreateCertificateResponse{}, httperror.CertificateParameterFail(err.Error())
	}

	// Setting Subject data for template and CSR
	templateSubject, err := SetCertSubject(template.Subject, signReq.CommonName)
	if err != nil {
		return types.CreateCertificateResponse{}, httperror.ProcessSubjectError(err.Error())
	}
	csrSubject := certReq.Subject
	csrSubject.CommonName = signReq.CommonName

	// Validate that the certificate request subject fields match those required by the template
	// TODO: Parameterize individual policies for each Subject field to specify whether they are optional matches or required
	fmt.Println(templateSubject.String())
	fmt.Println(csrSubject.String())
	if templateSubject.String() != csrSubject.String() {
		return types.CreateCertificateResponse{}, httperror.TemplateSubjectMismatch()
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
				return types.CreateCertificateResponse{}, httperror.InvalidKeyUsage(err.Error())
			}
		}
		if extension.Id.Equal([]int{2, 5, 29, 37}) { // ASN.1 OID for extended key usages
			extKeyUsage, err = ValidateExtKeyUsageConstraints(extension.Value, template.ExtKeyUsages)
			if err != nil {
				return types.CreateCertificateResponse{}, httperror.InvalidExtKeyUsage(err.Error())
			}
		}
	}

	// Validate that all the SANs from the HTTP request are either
	// explicitly permitted by the template or NOT explicitly denied
	// by the template
	err = ValidateSubjectAltNames(certReq.DNSNames, certReq.EmailAddresses, certReq.IPAddresses, certReq.URIs, template)
	if err != nil {
		return types.CreateCertificateResponse{}, httperror.InvalidSAN(err.Error())
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
		return types.CreateCertificateResponse{}, httperror.CreateCertificateFail(err.Error())
	}

	// Convert the certifcate objects into PEMs to be returned as strings
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
	pemCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	strSerialNumber, err := ConvertSerialIntToOctetString(serialNumber)
	if err != nil {
		return types.CreateCertificateResponse{}, httperror.SerialNumberConversionError(err.Error())
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
	err = backend.CreateCertificate(cert)
	if err != nil {
		return types.CreateCertificateResponse{}, httperror.CertWriteFail(err.Error())
	}
	return response, httperror.HTTPError{}
}

// CreateCert ------------------------
func CreateCert(certReq types.CreateCertReq, backend backend.Storage) (types.CreateCertificateResponse, httperror.HTTPError) {
	// Retrieve data from the storage backend and set all necessary parameters required to sign the certifcate
	template, serialNumber, ttl, sigAlgo, caCert, signingKey, err := PrepareCertificateParameters(certReq.TemplateName, certReq.TTL, backend)
	if err != nil {
		return types.CreateCertificateResponse{}, httperror.CertificateParameterFail(err.Error())
	}

	// Create a pkix.Name object from the Subject data in the template to
	// be used in the new Certificate object
	certSubject, err := SetCertSubject(template.Subject, certReq.CommonName)
	if err != nil {
		return types.CreateCertificateResponse{}, httperror.ProcessSubjectError(err.Error())
	}

	// Process the key usages stored in the requested template and return
	// them in a x509.KeyUsage object
	keyUsage, err := ProcessKeyUsages(template.KeyUsages)
	if err != nil {
		return types.CreateCertificateResponse{}, httperror.InvalidKeyUsage(err.Error())
	}

	// Process the extended key usages stored in the requested template and return
	// them in a x509.ExtendedKeyUsage object
	extKeyUsage, err := ProcessExtKeyUsages(template.ExtKeyUsages)
	if err != nil {
		return types.CreateCertificateResponse{}, httperror.InvalidExtKeyUsage(err.Error())
	}

	// Process the request's Subject Alternate Name fields into arrays specific to each
	// type of SAN, then validate that the requested SANs are permitted/not excluded by
	// the template
	dnsNames, emailAddresses, ipAddresses, URIs, err := ProcessSubjectAltNames(certReq.AltNames)
	if err != nil {
		return types.CreateCertificateResponse{}, httperror.ProcessSANError(err.Error())
	}
	err = ValidateSubjectAltNames(dnsNames, emailAddresses, ipAddresses, URIs, template)
	if err != nil {
		return types.CreateCertificateResponse{}, httperror.InvalidSAN(err.Error())
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
		return types.CreateCertificateResponse{}, httperror.KeygenError(err.Error())
	}

	derCert, err := x509.CreateCertificate(rand.Reader, &newCert, caCert, clientPubKey, signingKey)
	if err != nil {
		return types.CreateCertificateResponse{}, httperror.CreateCertificateFail(err.Error())
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
			return types.CreateCertificateResponse{}, httperror.ECDSAKeyError(err.Error())
		}
		pemPrivKey = pem.EncodeToMemory(&pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: ecKey})
	case "ED25519":
		pemPrivKey = pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: clientPrivKey.(ed25519.PrivateKey)})
	}

	strSerialNumber, err := ConvertSerialIntToOctetString(serialNumber)
	if err != nil {
		return types.CreateCertificateResponse{}, httperror.SerialNumberConversionError(err.Error())
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

	err = backend.CreateCertificate(cert)
	if err != nil {
		return types.CreateCertificateResponse{}, httperror.CertWriteFail(err.Error())
	}

	return response, httperror.HTTPError{}
}

// GetCert ----------------------
func GetCert(serialNumber string, backend backend.Storage) (types.PEMCertificate, httperror.HTTPError) {
	// Convert the serial number into a format that is usable by the x509 library
	intSerialNumber, err := ConvertSerialOctetStringToInt(serialNumber)
	if err != nil {
		return types.PEMCertificate{}, httperror.SerialNumberConversionError(err.Error())
	}

	// Retrieve base64 encoded certificate from backend, then decode and convert to PEM
	certificate, err := backend.GetCertificate(intSerialNumber)
	if err != nil {
		return types.PEMCertificate{}, httperror.StorageReadFail(err.Error())
	}
	derCert, err := base64.StdEncoding.DecodeString(certificate)
	if err != nil {
		return types.PEMCertificate{}, httperror.DecodeCertError(err.Error())
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
	response := types.PEMCertificate{
		Certificate: string(pemCert),
	}
	return response, httperror.HTTPError{}
}

// ListCerts ---------------------
func ListCerts(backend backend.Storage) (types.CertificateListResponse, httperror.HTTPError) {
	serialNumberList, err := backend.ListCertificates()
	if err != nil {
		return types.CertificateListResponse{}, httperror.StorageReadFail(err.Error())
	}

	retSerialNumbers := []string{}
	for _, serialNumber := range serialNumberList {
		strSerialNumber, err := ConvertSerialIntToOctetString(serialNumber)
		if err != nil {
			return types.CertificateListResponse{}, httperror.SerialNumberConversionError(err.Error())
		}
		retSerialNumbers = append(retSerialNumbers, strSerialNumber)
	}

	response := types.CertificateListResponse{
		Certificates: retSerialNumbers,
	}
	return response, httperror.HTTPError{}
}

// RevokeCert -----------------
func RevokeCert(crlReq types.RevokeRequest, backend backend.Storage) httperror.HTTPError {
	// Capture the numeric reason code, certificate revocation time, and serial number
	// used to generate the revocation entry
	reasonCode := -1
	var err error
	if crlReq.Reason != "" {
		reasonCode, err = ReturnReasonCode(crlReq.Reason)
		if err != nil {
			return httperror.ParseReasonFail(err.Error())
		}
	}
	revokeTime := time.Now()
	intSerialNum, err := ConvertSerialOctetStringToInt(crlReq.SerialNumber)
	if err != nil {
		return httperror.SerialNumberConversionError(err.Error())
	}

	err = backend.RevokeCertificate(intSerialNum, reasonCode, revokeTime)
	if err != nil {
		return httperror.RevocationFail(err.Error())
	}

	// Loop through all revoke certificates from the storage backend (including that being revoked by this method call)
	// and generate a pkix.RevokedCertificates array to be used for the generation of a new
	// CRL
	revokedCertificates, err := backend.GetRevokedCerts()
	if err != nil {
		return httperror.StorageReadFail(err.Error())
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
			return httperror.SerialNumberConversionError(err.Error())
		}
		crlEntry := pkix.RevokedCertificate{
			SerialNumber:   intSerialNum,
			RevocationTime: revokedCertificate.RevocationDate,
			Extensions:     crlExtensions,
		}
		revokedCertList = append(revokedCertList, crlEntry)
	}

	// Retrieve the base64 encoded signing key from storage backend and decode it
	encodedSigningKey, err := backend.GetSigningKey()
	if err != nil {
		return httperror.SigningKeyReadFail(err.Error())
	}
	decodedSigningKey, err := base64.StdEncoding.DecodeString(encodedSigningKey)

	// Try to parse the private key using PKCS8, and if it fails attempt to use the recommended
	// parsing format from the PKCS8 error
	signingKey, err := x509.ParsePKCS8PrivateKey(decodedSigningKey)
	if err != nil {
		if strings.Contains(err.Error(), "ParsePKCS1PrivateKey") {
			signingKey, err = x509.ParsePKCS1PrivateKey(decodedSigningKey)
			if err != nil {
				return httperror.ParseSigningKeyError(err.Error())
			}
		} else {
			return httperror.ParseSigningKeyError(err.Error())
		}
	}

	// Retrieve the base64 encoded signing key from storage backend and decode it
	encodedCACert, err := backend.GetSigningCert()
	if err != nil {
		return httperror.StorageReadFail(err.Error())
	}
	derCACert, err := base64.StdEncoding.DecodeString(encodedCACert)
	if err != nil {
		return httperror.DecodeCertError(err.Error())
	}
	caCert, err := x509.ParseCertificate(derCACert)
	if err != nil {
		return httperror.ParseCertificateError(err.Error())
	}
	newCRL, err := caCert.CreateCRL(rand.Reader, signingKey, revokedCertList, revokeTime, revokeTime.Add(time.Hour*12))
	if err != nil {
		return httperror.CreateCRLFail(err.Error())
	}

	err = backend.WriteCRL(base64.StdEncoding.EncodeToString(newCRL))
	if err != nil {
		return httperror.WriteCRLFail(err.Error())
	}
	return httperror.HTTPError{}
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
