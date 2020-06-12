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
// Handler that receives parameters for generating a new intermediate CA and creates
// a CSR to be signed by the enterprise root CA (or another intermediate CA in the chain)
// and creates a new signing key that is stored in backened storage to be used for all
// new certificate generation. Alternatively, if the 'selfSigned' property is passed in
// the request as true, it will generate and return a self-signed CA certificate
func (p *Pki) GenerateIntermediateCSRHandler(w http.ResponseWriter, r *http.Request) {
	reqBody, err := ioutil.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "CPKIGI001: Unable to read request body -  "+err.Error(), http.StatusBadRequest)
		return
	}

	if !ValidateContentType(r.Header, "application/json") {
		http.Error(w, "CPKIGI002: Invalid HTTP Content-Type header - expected application/json", http.StatusUnsupportedMediaType)
		return
	}

	authHeader := r.Header.Get("Authorization")
	err = p.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		http.Error(w, "CPKIGI003: Invalid authentication from header - "+err.Error(), http.StatusUnauthorized)
		return
	}

	err = p.Backend.GetAccessControl().AdminOnly(authHeader)
	if err != nil {
		http.Error(w, "CPKIGI004: Not authorized to generate intermediate CA CSR - "+err.Error(), http.StatusForbidden)
		return
	}

	var intermediateRequest types.IntermediateRequest
	err = json.Unmarshal(reqBody, &intermediateRequest)
	if err != nil {
		http.Error(w, "CPKIGI005: Not able to unmarshal request body data - "+err.Error(), http.StatusBadRequest)
		return
	}

	signPrivKey, signPubKey, err := GenerateKeys(intermediateRequest.KeyAlgo, intermediateRequest.KeyBits)
	if err != nil {
		http.Error(w, "CPKIGI006: Error generating signing key - "+err.Error(), http.StatusBadRequest)
		return
	}

	certSubject, err := SetCertSubject(intermediateRequest.Subject, intermediateRequest.CommonName)
	if err != nil {
		http.Error(w, "CPKIGI007: Error processing signing certificate subject - "+err.Error(), http.StatusInternalServerError)
		return
	}

	dnsNames, emailAddresses, ipAddresses, URIs, err := ProcessSubjectAltNames(intermediateRequest.AltNames)
	if err != nil {
		http.Error(w, "CPKIGI008: Error processing SANs - "+err.Error(), http.StatusBadRequest)
		return
	}

	// Set X.509 extensions to specify that this CSR is for a CA certificate
	extraExtensions := []pkix.Extension{}
	caConstraint := types.CABasicConstraints{
		CA: true,
	}
	// Convert extension type to ASN.1 format to be added to certificate request
	encodedCaConstraint, err := asn1.Marshal(caConstraint)
	if err != nil {
		http.Error(w, "CPKIGI009: Unable to marshal CA basic constraints to ASN.1 format - "+err.Error(), http.StatusBadRequest)
		return
	}
	isCAExtension := pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 19}, // Object identifier for certificate property "IsCA"
		Critical: true,
		Value:    encodedCaConstraint,
	}

	// Required key usages for CA certificate
	keyUsage := x509.KeyUsageCRLSign | x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature

	var bsKeyUsage asn1.BitString
	// Reverse the bits of the allowed usages integer to account for big-endian ASN.1 bit string
	// that it will be compared against
	keyUsage = x509.KeyUsage(bits.Reverse16(uint16(keyUsage)))
	bsKeyUsage.BitLength = 9
	// Bitwise separation of the 16-bit allowedUsages variable into a 2-byte byte slice
	// to be encoded into an ASN.1 BitString
	bsKeyUsage.Bytes = []byte{byte(0xff & (keyUsage >> 8)), byte(0xff & keyUsage)}
	encodedKeyUsage, err := asn1.Marshal(bsKeyUsage)
	if err != nil {
		http.Error(w, "CPKIGI010: Unable to marshal CA key usages to ASN.1 format - "+err.Error(), http.StatusBadRequest)
		return
	}
	keyUsageExtension := pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 15}, // Object identifier for certificate property KeyUsages
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
		http.Error(w, "CPKIGI011: No matching signature algorithm found in requested template", http.StatusInternalServerError)
		return
	}
	var intermediateResponse types.PEMIntermediate

	if !intermediateRequest.SelfSigned { // Generate a CSR if self-signed is not passed or is passed as false
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
			http.Error(w, "CPKIGI012: Error while generating new CSR - "+err.Error(), http.StatusInternalServerError)
			return
		}

		pemSignCSR := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: signCSR})
		intermediateResponse = types.PEMIntermediate{CSR: string(pemSignCSR)}

	} else { // Generate a self-signed CA certificate
		serialNumber, err := p.GenerateSerialNumber()
		if err != nil {
			http.Error(w, "CPKIGI013: Error generating serial number - "+err.Error(), http.StatusInternalServerError)
			return
		}
		certTemplate := x509.Certificate{
			SerialNumber:          serialNumber,
			SignatureAlgorithm:    sigAlgo,
			Subject:               certSubject,
			DNSNames:              dnsNames,
			EmailAddresses:        emailAddresses,
			IPAddresses:           ipAddresses,
			URIs:                  URIs,
			BasicConstraintsValid: true,
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		signCert, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, signPubKey, signPrivKey)
		if err != nil {
			http.Error(w, "CPKIGI014: Error while generating new self signed cert - "+err.Error(), http.StatusInternalServerError)
			return
		}
		pemSignCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signCert})
		intermediateResponse = types.PEMIntermediate{SelfSignedCert: string(pemSignCert)}
		err = p.Backend.WriteSigningCert(base64.StdEncoding.EncodeToString(signCert))
		if err != nil {
			http.Error(w, "CPKIGI015: Error writing self-signed CA certificate to backend storage - "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	var keyBytes []byte
	// Capture the DER format of the new signing key to be written to backend storage
	switch intermediateRequest.KeyAlgo {
	case "RSA":
		keyBytes = x509.MarshalPKCS1PrivateKey(signPrivKey.(*rsa.PrivateKey))
	case "ECDSA":
		keyBytes, err = x509.MarshalECPrivateKey(signPrivKey.(*ecdsa.PrivateKey))
		if err != nil {
			http.Error(w, "CPKIGI016: Unable to marshal new ECDSA private key - "+err.Error(), http.StatusInternalServerError)
			return
		}
	case "ED25519":
		keyBytes = signPrivKey.(ed25519.PrivateKey)
	}

	err = p.Backend.WriteSigningKey(base64.StdEncoding.EncodeToString(keyBytes))
	if err != nil {
		http.Error(w, "CPKIGI017: Error while writing signing key to Conjur - "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(intermediateResponse)
	if err != nil {
		http.Error(w, "CPKIGI018: Error encoding intermediate CA/CSR response - "+err.Error(), http.StatusInternalServerError)
	}
}

// SetIntermediateCertHandler ----------------------------------------------
// Handler that accepts the new intermediate CA certificate after it has been signed
// by the enterprise root CA (or another intermediate CA in the chain) and sets it
// as the "signing certificate" for the PKI service
func (p *Pki) SetIntermediateCertHandler(w http.ResponseWriter, r *http.Request) {
	reqBody, err := ioutil.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "CPKISI001: Unable to read request body - "+err.Error(), http.StatusBadRequest)
		return
	}

	if !ValidateContentType(r.Header, "application/json") {
		http.Error(w, "CPKISI002: Invalid HTTP Content-Type header - expected application/json", http.StatusUnsupportedMediaType)
		return
	}

	authHeader := r.Header.Get("Authorization")
	err = p.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		http.Error(w, "CPKISI003: Invalid authentication from header -  "+err.Error(), http.StatusUnauthorized)
		return
	}

	err = p.Backend.GetAccessControl().AdminOnly(authHeader)
	if err != nil {
		http.Error(w, "CPKISI004: Not authorized to set intermediate CA certificate - "+err.Error(), http.StatusForbidden)
		return
	}

	var signedCert types.PEMCertificate
	err = json.Unmarshal(reqBody, &signedCert)
	if err != nil {
		http.Error(w, "CPKISI005: Not able to unmarshal request body data - "+err.Error(), http.StatusBadRequest)
		return
	}

	pemCert, rest := pem.Decode([]byte(signedCert.Certificate))
	if len(rest) > 0 {
		http.Error(w, "CPKISI006: The signed certificate is not in valid PEM format", http.StatusBadRequest)
		return
	}
	derCert := pemCert.Bytes
	certificate, err := x509.ParseCertificate(derCert)
	if err != nil {
		http.Error(w, "CPKSISI007: Error parsing the signed certificate - "+err.Error(), http.StatusInternalServerError)
		return
	}

	certificatePublicKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		http.Error(w, "CPKISI008: Error parsing the public key from certificate - "+err.Error(), http.StatusInternalServerError)
		return
	}

	strSigningKey, err := p.Backend.GetSigningKey()
	if err != nil {
		http.Error(w, "CPKISI009: Error reading signing key from storage backend - "+err.Error(), http.StatusBadRequest)
		return
	}

	byteSigningKey, err := base64.StdEncoding.DecodeString(strSigningKey)
	if err != nil {
		http.Error(w, "CPKISI010: Error decoding signing key from storage backend - "+err.Error(), http.StatusInternalServerError)
		return
	}
	var signingKey crypto.PrivateKey
	switch certificate.SignatureAlgorithm {
	case x509.SHA256WithRSA:
		signingKey, err = x509.ParsePKCS1PrivateKey(byteSigningKey)
		if err != nil {
			http.Error(w, "CPKISI011: Error parsing the signing key - "+err.Error(), http.StatusInternalServerError)
			return
		}
		signingPublicKey, err := x509.MarshalPKIXPublicKey(&signingKey.(*rsa.PrivateKey).PublicKey)
		if err != nil {
			http.Error(w, "CPKISI012: Error parsing the public key from the signing key - "+err.Error(), http.StatusInternalServerError)
			return
		}
		if string(signingPublicKey) != string(certificatePublicKey) {
			http.Error(w, "CPKISI013: Certificate public key does not match the signing key", http.StatusBadRequest)
			return
		}
	case x509.ECDSAWithSHA256:
		signingKey, err = x509.ParseECPrivateKey(byteSigningKey)
		if err != nil {
			http.Error(w, "CPKISI011: Error parsing the signing key - "+err.Error(), http.StatusInternalServerError)
			return
		}
		signingPublicKey, err := x509.MarshalPKIXPublicKey(signingKey.(ecdsa.PrivateKey).PublicKey)
		if err != nil {
			http.Error(w, "CPKISI012: Error parsing the public key from the signing key - "+err.Error(), http.StatusInternalServerError)
			return
		}
		if string(signingPublicKey) != string(certificatePublicKey) {
			http.Error(w, "CPKISI013: Certificate public key does not match the signing key", http.StatusBadRequest)
			return
		}
	case x509.PureEd25519:
		signingPublicKey, err := x509.MarshalPKIXPublicKey(ed25519.PrivateKey(byteSigningKey).Public())
		if err != nil {
			http.Error(w, "CPKISI012: Error parsing the public key from the signing key - "+err.Error(), http.StatusInternalServerError)
			return
		}
		if string(signingPublicKey) != string(certificatePublicKey) {
			http.Error(w, "CPKISI013: Certificate public key does not match the signing key", http.StatusBadRequest)
			return
		}
	}
	err = p.Backend.WriteSigningCert(base64.StdEncoding.EncodeToString(derCert))
	if err != nil {
		http.Error(w, "CPKISI014: Error writing the intermediate CA certificate to storage backend - "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// GetCAHandler ----------------------------------------------------------------------
// Handler to retrieve the base64-encoded DER intermediate CA certificate from the storage backend
// and return it in PEM format
func (p *Pki) GetCAHandler(w http.ResponseWriter, r *http.Request) {
	encodedCA, err := p.Backend.GetSigningCert()
	if err != nil {
		http.Error(w, "CPKICA01: Error reading intermediate CA certificate from storage backend - "+err.Error(), http.StatusInternalServerError)
		return
	}
	decodedCA, err := base64.StdEncoding.DecodeString(encodedCA)
	if err != nil {
		http.Error(w, "CPKICA002: Error decoding signing key from storage backend - "+err.Error(), http.StatusInternalServerError)
		return
	}
	pemCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: decodedCA})
	_, err = w.Write(pemCA)
	if err != nil {
		http.Error(w, "CPKICA003: Error writing HTTP response - "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// GetCAChainHandler -----------------------------------------------------------------
// Handler to retrieve the base64-encoded DER intermediate CA certificates associated with
// the CA chain from the storage backend and return them in PEM format
func (p *Pki) GetCAChainHandler(w http.ResponseWriter, r *http.Request) {

	// Set the first certificate in the chain to the PKI service's internal
	// intermediate CA certificate
	encodedCA, err := p.Backend.GetSigningCert()
	if err != nil {
		http.Error(w, "CPKIGC01: Error reading intermediate CA certificate from storage backend - "+err.Error(), http.StatusInternalServerError)
		return
	}
	decodedCA, err := base64.StdEncoding.DecodeString(encodedCA)
	if err != nil {
		http.Error(w, "CPKIGC002: Error decoding signing key from storage backend - "+err.Error(), http.StatusInternalServerError)
		return
	}
	caChain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: decodedCA}))

	// Retrieve the rest of the CA chain from the storage backend to an array and
	// loop through each of them, converting to PEM string and appending to the
	// current CA chain
	encodedBundle, err := p.Backend.GetCAChain()
	if err != nil {
		http.Error(w, "CPKIGC003: Error reading CA chain from storage backend - "+err.Error(), http.StatusInternalServerError)
		return
	}
	for _, encodedCert := range encodedBundle {
		derCert, err := base64.StdEncoding.DecodeString(encodedCert)
		if err != nil {
			http.Error(w, "CPKIGC004: Error processing CA chain - "+err.Error(), http.StatusInternalServerError)
			return
		}
		pemCert := pem.Block{Type: "CERTIFICATE", Bytes: derCert}
		caChain += string(pem.EncodeToMemory(&pemCert))
	}
	caChainBundle := types.PEMCertificateBundle{
		CertBundle: caChain,
	}

	err = json.NewEncoder(w).Encode(caChainBundle)
	if err != nil {
		http.Error(w, "CPKIGC005: Error encoding HTTP response - "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// SetCAChainHandler -----------------------------------------------------------------
// Handler to capture a PEM encoded certificate bundle from the request and parse it
// into individual DER certificates. Each of these certificates are stored in base64
// format in the storage backend
func (p *Pki) SetCAChainHandler(w http.ResponseWriter, r *http.Request) {
	reqBody, err := ioutil.ReadAll(r.Body)

	if err != nil {
		http.Error(w, "CPKISC001: Unable to read request body - "+err.Error(), http.StatusBadRequest)
		return
	}

	if !ValidateContentType(r.Header, "application/json") {
		http.Error(w, "CPKISC002: Invalid HTTP Content-Type header - expected application/json", http.StatusUnsupportedMediaType)
		return
	}

	authHeader := r.Header.Get("Authorization")
	err = p.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		http.Error(w, "CPKISC003: Invalid authentication from header - "+err.Error(), http.StatusUnauthorized)
		return
	}

	err = p.Backend.GetAccessControl().AdminOnly(authHeader)
	if err != nil {
		http.Error(w, "CPKISC004: Not authorized to set CA chain - "+err.Error(), http.StatusForbidden)
		return
	}

	var pemBundle types.PEMCertificateBundle
	err = json.Unmarshal(reqBody, &pemBundle)
	if err != nil {
		http.Error(w, "CPKISC005: Not able to unmarshal request body data - "+err.Error(), http.StatusBadRequest)
		return
	}
	var certBundle []string
	// Decode each PEM block from the certificate bundle that was passed in
	// the request, and continue looping until no valid PEM blocks are found
	for pemCert, _ := pem.Decode([]byte(pemBundle.CertBundle)); pemCert != nil; {
		derCert := pemCert.Bytes
		encodedCert := base64.StdEncoding.EncodeToString(derCert)
		certBundle = append(certBundle, encodedCert)
	}
	err = p.Backend.WriteCAChain(certBundle)
	if err != nil {
		http.Error(w, "CPKISC006: Error writing CA chain to storage backend - "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// GetCRLHandler ----------------------------------------------------
// Handler to retrieve the DER encoded CRL from the storage backend
func (p *Pki) GetCRLHandler(w http.ResponseWriter, r *http.Request) {
	encodedCRL, err := p.Backend.GetCRL()
	if err != nil {
		http.Error(w, "CPKICR001: Error reading the CRL from storage backend - "+err.Error(), http.StatusInternalServerError)
		return
	}
	decodedCRL, err := base64.StdEncoding.DecodeString(encodedCRL)
	if err != nil {
		http.Error(w, "CPKICR002: Error decoding the CRL from base64 - "+err.Error(), http.StatusInternalServerError)
		return
	}
	_, err = w.Write(decodedCRL)
	if err != nil {
		http.Error(w, "CPKICR003: Error writing HTTP response - "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// PurgeHandler -----------------------------------------------------
// Handler that will purge all expired certificates from both the certificate
// repository in the storage backend, as well as the CRL, within a given buffer
// time that is passed in the request
func (p *Pki) PurgeHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	err := p.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		http.Error(w, "CPKIPU001: Invalid authentication from header - "+err.Error(), http.StatusUnauthorized)
		return
	}

	err = p.Backend.GetAccessControl().Purge(authHeader)
	if err != nil {
		http.Error(w, "CPKIPU002: Not authorized to purge certificate repository - "+err.Error(), http.StatusForbidden)
		return
	}
}

// PurgeCRLHandler --------------------------------------------------
// Handler that will purge all expired certificates from the CRL
// within a given buffer time that is passed in the request
func (p *Pki) PurgeCRLHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	err := p.Backend.GetAccessControl().Authenticate(authHeader)
	if err != nil {
		http.Error(w, "CPKIPC001: Invalid authentication from header - "+err.Error(), http.StatusUnauthorized)
		return
	}

	err = p.Backend.GetAccessControl().CRLPurge(authHeader)
	if err != nil {
		http.Error(w, "CPKIPC002: Not authorized to purge CRL - "+err.Error(), http.StatusForbidden)
		return
	}
}

/********************************************
TODO:
func OSCPRespHandler(w http.ResponseWriter, r *http.Request) {

}
******************************************/
