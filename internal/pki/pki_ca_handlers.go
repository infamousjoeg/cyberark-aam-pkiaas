package pki

import (
	"crypto"
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
	"io/ioutil"
	"math/bits"
	"net/http"

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
	if err != nil {
		http.Error(w, "Unable to process request body data.  JSON Unmarshal returned error: "+err.Error(), http.StatusBadRequest)
		return
	}

	signPrivKey, _, err := GenerateKeys(intermediateRequest.KeyAlgo, intermediateRequest.KeyBits)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	certSubject, err := SetCertSubject(intermediateRequest.Subject, intermediateRequest.CommonName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	dnsNames, emailAddresses, ipAddresses, URIs, err := ProcessSubjectAltNames(intermediateRequest.AltNames)
	if err != nil {
		http.Error(w, "Error handling request Subject Alternate Names: "+err.Error(), http.StatusBadRequest)
		return
	}

	extraExtensions := []pkix.Extension{}
	caConstraint := types.CABasicConstraints{
		CA: true,
	}
	encodedCaConstraint, err := asn1.Marshal(caConstraint)
	if err != nil {
		http.Error(w, "Error marshaling CA basic constraints in ASN.1 format: "+err.Error(), http.StatusBadRequest)
		return
	}
	isCAExtension := pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
		Critical: true,
		Value:    encodedCaConstraint,
	}

	keyUsage := x509.KeyUsageCRLSign | x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	var bsKeyUsage asn1.BitString
	keyUsage = x509.KeyUsage(bits.Reverse16(uint16(keyUsage)))
	bsKeyUsage.BitLength = 9
	bsKeyUsage.Bytes = []byte{byte(0xff & (keyUsage >> 8)), byte(0xff & keyUsage)}
	encodedKeyUsage, err := asn1.Marshal(bsKeyUsage)
	if err != nil {
		http.Error(w, "Error marshaling CA key usages in ASN.1 format: "+err.Error(), http.StatusBadRequest)
		return
	}
	keyUsageExtension := pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 15},
		Critical: true,
		Value:    encodedKeyUsage,
	}

	keyType := fmt.Sprintf("%T", signPrivKey)

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

	extraExtensions = append(extraExtensions, isCAExtension)
	extraExtensions = append(extraExtensions, keyUsageExtension)
	signRequest := x509.CertificateRequest{
		SignatureAlgorithm: sigAlgo,
		Subject:            certSubject,
		DNSNames:           dnsNames,
		EmailAddresses:     emailAddresses,
		IPAddresses:        ipAddresses,
		URIs:               URIs,
		ExtraExtensions:    extraExtensions,
	}
	signCSR, err := x509.CreateCertificateRequest(rand.Reader, &signRequest, signPrivKey)
	if err != nil {
		http.Error(w, "Unable to generate new certificate request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	pemSignCSR := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: signCSR})
	csrResponse := types.PEMCSR{CSR: string(pemSignCSR)}

	var keyBytes []byte
	switch intermediateRequest.KeyAlgo {
	case "RSA":
		keyBytes = x509.MarshalPKCS1PrivateKey(signPrivKey.(*rsa.PrivateKey))
	case "ECDSA":
		keyBytes, err = x509.MarshalECPrivateKey(signPrivKey.(*ecdsa.PrivateKey))
		if err != nil {
			http.Error(w, "Unable to successfully marshal new ECDSA key into PEM format for return", http.StatusInternalServerError)
			return
		}
	case "ED25519":
		keyBytes = signPrivKey.(ed25519.PrivateKey)
	}
	err = WriteSigningKeyToDAP(base64.StdEncoding.EncodeToString(keyBytes))

	json.NewEncoder(w).Encode(csrResponse)
}

// SetIntermediateCertHandler ----------------------------------------------
func SetIntermediateCertHandler(w http.ResponseWriter, r *http.Request) {
	reqBody, err := ioutil.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "Unable to read request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if !ValidateContentType(r.Header, "application/json") {
		http.Error(w, "Invalid content type: expected application/json", http.StatusUnsupportedMediaType)
		return
	}
	var signedCert types.PEMCertificate
	err = json.Unmarshal(reqBody, &signedCert)
	pemCert, rest := pem.Decode([]byte(signedCert.Certificate))
	if len(rest) > 0 {
		http.Error(w, "The signed certificate is not in a valid PEM format", http.StatusBadRequest)
		return
	}
	derCert := pemCert.Bytes
	certificate, err := x509.ParseCertificate(derCert)
	if err != nil {
		http.Error(w, "Error parsing the signed certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	certificatePublicKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		http.Error(w, "Error parsing the public key from the signed certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	strSigningKey, err := GetSigningCertFromDAP()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	byteSigningKey, err := base64.StdEncoding.DecodeString(strSigningKey)
	var signingKey crypto.PrivateKey
	switch certificate.SignatureAlgorithm {
	case x509.SHA256WithRSA:
		signingKey, err = x509.ParsePKCS1PrivateKey(byteSigningKey)
		signingPublicKey, err := x509.MarshalPKIXPublicKey(signingKey.(rsa.PrivateKey).PublicKey)
		if err != nil {
			http.Error(w, "Error parsing the public key from the signing key: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if string(signingPublicKey) != string(certificatePublicKey) {
			http.Error(w, "The public key in the submitted certificate does not match the key used to sign it", http.StatusBadRequest)
			return
		}
	case x509.ECDSAWithSHA256:
		signingKey, err = x509.ParseECPrivateKey(byteSigningKey)
		signingPublicKey, err := x509.MarshalPKIXPublicKey(signingKey.(ecdsa.PrivateKey).PublicKey)
		if err != nil {
			http.Error(w, "Error parsing the public key from the signing key: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if string(signingPublicKey) != string(certificatePublicKey) {
			http.Error(w, "The public key in the submitted certificate does not match the key used to sign it", http.StatusBadRequest)
			return
		}
	case x509.PureEd25519:
		signingPublicKey, err := x509.MarshalPKIXPublicKey(ed25519.PrivateKey(byteSigningKey).Public())
		if err != nil {
			http.Error(w, "Error parsing the public key from the signing key: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if string(signingPublicKey) != string(certificatePublicKey) {
			http.Error(w, "The public key in the submitted certificate does not match the key used to sign it", http.StatusBadRequest)
			return
		}
	}
	WriteSigningCertToDAP(base64.StdEncoding.EncodeToString(derCert))
}

// GetCAHandler ----------------------------------------------------------------------
func GetCAHandler(w http.ResponseWriter, r *http.Request) {
	encodedCA, err := GetSigningCertFromDAP()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	decodedCA, err := base64.StdEncoding.DecodeString(encodedCA)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	pemCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: decodedCA})
	w.Write(pemCA)
}

// GetCAChainHandler -----------------------------------------------------------------
func GetCAChainHandler(w http.ResponseWriter, r *http.Request) {
	caChain := ""
	encodedBundle, err := GetCAChainFromDAP()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	for _, encodedCert := range encodedBundle {
		derCert, err := base64.StdEncoding.DecodeString(encodedCert)
		if err != nil {
			http.Error(w, "Error processing CA chain: "+err.Error(), http.StatusInternalServerError)
		}
		pemCert := pem.Block{Type: "CERTIFICATE", Bytes: derCert}
		caChain += string(pem.EncodeToMemory(&pemCert))
	}
	caChainBundle := types.PEMCertificateBundle{
		CertBundle: caChain,
	}

	json.NewEncoder(w).Encode(caChainBundle)
}

// SetCAChainHandler -----------------------------------------------------------------
func SetCAChainHandler(w http.ResponseWriter, r *http.Request) {
	reqBody, err := ioutil.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}

	if !ValidateContentType(r.Header, "application/json") {
		http.Error(w, "Invalid content type: expected application/json", http.StatusUnsupportedMediaType)
		return
	}

	var pemBundle types.PEMCertificateBundle
	err = json.Unmarshal(reqBody, &pemBundle)
	if err != nil {
		http.Error(w, "Unable to process request body data.  JSON Unmarshal returned error: "+err.Error(), http.StatusBadRequest)
		return
	}
	var certBundle []string
	for pemCert, remainder := pem.Decode([]byte(pemBundle.CertBundle)); len(remainder) > 0; {
		derCert := pemCert.Bytes
		encodedCert := base64.StdEncoding.EncodeToString(derCert)
		certBundle = append(certBundle, encodedCert)
	}
	err = WriteCAChainToDAP(certBundle)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// GetCRLHandler ----------------------------------------------------
func GetCRLHandler(w http.ResponseWriter, r *http.Request) {

}

// PurgeHandler -----------------------------------------------------
func PurgeHandler(w http.ResponseWriter, r *http.Request) {

}

// PurgeCRLHandler --------------------------------------------------
func PurgeCRLHandler(w http.ResponseWriter, r *http.Request) {

}
