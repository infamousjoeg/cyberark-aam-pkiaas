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
	"encoding/pem"
	"fmt"
	"math/bits"
	"time"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/httperror"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// GenerateIntermediate -------------------------------
func GenerateIntermediate(intermediateRequest types.IntermediateRequest, selfSigned bool, backend backend.Storage) (types.PEMIntermediate, httperror.HTTPError) {
	signPrivKey, signPubKey, err := GenerateKeys(intermediateRequest.KeyAlgo, intermediateRequest.KeyBits)
	if err != nil {
		return types.PEMIntermediate{}, httperror.KeygenError(err.Error())
	}

	certSubject, err := SetCertSubject(intermediateRequest.Subject, intermediateRequest.CommonName)
	if err != nil {
		return types.PEMIntermediate{}, httperror.ProcessSubjectError(err.Error())
	}

	dnsNames, emailAddresses, ipAddresses, URIs, err := ProcessSubjectAltNames(intermediateRequest.AltNames)
	if err != nil {
		return types.PEMIntermediate{}, httperror.ProcessSANError(err.Error())
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
		return types.PEMIntermediate{}, httperror.BadSigAlgo(err.Error())
	}
	var intermediateResponse types.PEMIntermediate
	httpErr := httperror.HTTPError{}

	var keyBytes []byte
	// Capture the DER format of the new signing key to be written to backend storage
	switch intermediateRequest.KeyAlgo {
	case "RSA":
		keyBytes = x509.MarshalPKCS1PrivateKey(signPrivKey.(*rsa.PrivateKey))
	case "ECDSA":
		keyBytes, err = x509.MarshalECPrivateKey(signPrivKey.(*ecdsa.PrivateKey))
		if err != nil {
			return types.PEMIntermediate{}, httperror.ECDSAKeyError(err.Error())
		}
	case "ED25519":
		keyBytes = signPrivKey.(ed25519.PrivateKey)
	}

	err = backend.WriteSigningKey(base64.StdEncoding.EncodeToString(keyBytes))
	if err != nil {
		return types.PEMIntermediate{}, httperror.SigningKeyWriteFail(err.Error())
	}
	if !selfSigned { // Generate a CSR if self-signed is not passed or is passed as false

		signRequest := x509.CertificateRequest{
			SignatureAlgorithm: sigAlgo,
			Subject:            certSubject,
			DNSNames:           dnsNames,
			EmailAddresses:     emailAddresses,
			IPAddresses:        ipAddresses,
			URIs:               URIs,
		}
		intermediateResponse, httpErr = CreateIntermediateCSR(signRequest, signPrivKey)
		if httpErr != (httperror.HTTPError{}) {
			return types.PEMIntermediate{}, httpErr
		}

	} else { // Generate a self-signed CA certificate

		certTemplate := x509.Certificate{
			SignatureAlgorithm:    sigAlgo,
			Subject:               certSubject,
			NotBefore:             time.Now().UTC(),
			NotAfter:              time.Now().Add(time.Hour * 87600).UTC(),
			DNSNames:              dnsNames,
			EmailAddresses:        emailAddresses,
			IPAddresses:           ipAddresses,
			URIs:                  URIs,
			BasicConstraintsValid: true,
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		intermediateResponse, httpErr = CreateSelfSignedCert(certTemplate, signPrivKey, signPubKey, backend)
		if httpErr != (httperror.HTTPError{}) {
			return types.PEMIntermediate{}, httpErr
		}
	}

	return intermediateResponse, httpErr
}

// CreateIntermediateCSR Generates a CSR used for the intermediate signing CA and returns
// HTTPError if it fails
func CreateIntermediateCSR(signRequest x509.CertificateRequest, signPrivKey crypto.PrivateKey) (types.PEMIntermediate, httperror.HTTPError) {
	// Set X.509 extensions to specify that this CSR is for a CA certificate
	extraExtensions := []pkix.Extension{}
	caConstraint := types.CABasicConstraints{
		CA: true,
	}
	// Convert extension type to ASN.1 format to be added to certificate request
	encodedCaConstraint, err := asn1.Marshal(caConstraint)
	if err != nil {
		return types.PEMIntermediate{}, httperror.BasicConstraintError(err.Error())
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
		return types.PEMIntermediate{}, httperror.MarshalKeyUsageError(err.Error())
	}
	keyUsageExtension := pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 15}, // Object identifier for certificate property KeyUsages
		Critical: true,
		Value:    encodedKeyUsage,
	}

	extraExtensions = append(extraExtensions, isCAExtension)
	extraExtensions = append(extraExtensions, keyUsageExtension)

	signRequest.ExtraExtensions = extraExtensions
	signCSR, err := x509.CreateCertificateRequest(rand.Reader, &signRequest, signPrivKey)
	if err != nil {
		return types.PEMIntermediate{}, httperror.GenerateCSRFail(err.Error())
	}

	pemSignCSR := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: signCSR})
	return types.PEMIntermediate{CSR: string(pemSignCSR)}, httperror.HTTPError{}
}

// CreateSelfSignedCert Generates a self signed CA certificate for the PKI service and returns
// HTTPError if it fails
func CreateSelfSignedCert(certTemplate x509.Certificate, signPrivKey crypto.PrivateKey, signPubKey crypto.PublicKey, backend backend.Storage) (types.PEMIntermediate, httperror.HTTPError) {
	serialNumber, err := GenerateSerialNumber(backend)
	if err != nil {
		return types.PEMIntermediate{}, httperror.GenerateSerialFail(err.Error())
	}
	certTemplate.SerialNumber = serialNumber
	signCert, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, signPubKey, signPrivKey)
	if err != nil {
		return types.PEMIntermediate{}, httperror.GenerateSelfSignFail(err.Error())
	}
	pemSignCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signCert})
	err = backend.WriteSigningCert(base64.StdEncoding.EncodeToString(signCert))
	if err != nil {
		return types.PEMIntermediate{}, httperror.CertWriteFail(err.Error())
	}
	err = backend.WriteCAChain([]string{string(pemSignCert)})
	if err != nil {
		return types.PEMIntermediate{}, httperror.StorageWriteFail(err.Error())
	}
	httperr := CreateCRL([]types.RevokedCertificate{}, backend)
	if httperr != (httperror.HTTPError{}) {
		return types.PEMIntermediate{}, httperr
	}
	return types.PEMIntermediate{SelfSignedCert: string(pemSignCert)}, httperror.HTTPError{}
}

// SetIntermediateCertificate ----------------------------------------------------------
func SetIntermediateCertificate(signedCert types.PEMCertificate, backend backend.Storage) httperror.HTTPError {
	pemCert, rest := pem.Decode([]byte(signedCert.Certificate))
	if len(rest) > 0 {
		return httperror.InvalidCertificateFormat()
	}
	derCert := pemCert.Bytes
	certificate, err := x509.ParseCertificate(derCert)
	if err != nil {
		return httperror.ParseCertificateError(err.Error())
	}

	certificatePublicKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return httperror.CertificatePublicKeyError(err.Error())
	}

	strSigningKey, err := backend.GetSigningKey()
	if err != nil {
		return httperror.SigningKeyReadFail(err.Error())
	}

	byteSigningKey, err := base64.StdEncoding.DecodeString(strSigningKey)
	if err != nil {
		return httperror.DecodeSigningKeyError(err.Error())
	}
	var signingKey crypto.PrivateKey
	switch certificate.SignatureAlgorithm {
	case x509.SHA256WithRSA:
		signingKey, err = x509.ParsePKCS1PrivateKey(byteSigningKey)
		if err != nil {
			return httperror.ParseSigningKeyError(err.Error())
		}
		signingPublicKey, err := x509.MarshalPKIXPublicKey(&signingKey.(*rsa.PrivateKey).PublicKey)
		if err != nil {
			return httperror.ParsePublicKeyError(err.Error())
		}
		if string(signingPublicKey) != string(certificatePublicKey) {
			return httperror.PublicKeyMismatch()
		}
	case x509.ECDSAWithSHA256:
		signingKey, err = x509.ParseECPrivateKey(byteSigningKey)
		if err != nil {
			return httperror.ParseSigningKeyError(err.Error())
		}
		signingPublicKey, err := x509.MarshalPKIXPublicKey(signingKey.(ecdsa.PrivateKey).PublicKey)
		if err != nil {
			return httperror.ParsePublicKeyError(err.Error())
		}
		if string(signingPublicKey) != string(certificatePublicKey) {
			return httperror.PublicKeyMismatch()
		}
	case x509.PureEd25519:
		signingPublicKey, err := x509.MarshalPKIXPublicKey(ed25519.PrivateKey(byteSigningKey).Public())
		if err != nil {
			return httperror.ParseSigningKeyError(err.Error())
		}
		if string(signingPublicKey) != string(certificatePublicKey) {
			return httperror.ParsePublicKeyError(err.Error())
		}
	}
	err = backend.WriteSigningCert(base64.StdEncoding.EncodeToString(derCert))
	if err != nil {
		return httperror.CertWriteFail(err.Error())
	}
	err = backend.WriteCAChain([]string{signedCert.Certificate})
	if err != nil {
		return httperror.StorageWriteFail(err.Error())
	}
	httperr := CreateCRL([]types.RevokedCertificate{}, backend)
	if httperr != (httperror.HTTPError{}) {
		return httperr
	}
	return httperror.HTTPError{}
}

// GetCA ------------------
func GetCA(backend backend.Storage) ([]byte, httperror.HTTPError) {
	encodedCA, err := backend.GetSigningCert()
	if err != nil {
		return nil, httperror.StorageReadFail(err.Error())
	}
	decodedCA, err := base64.StdEncoding.DecodeString(encodedCA)
	if err != nil {
		return nil, httperror.DecodeCertError(err.Error())
	}
	pemCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: decodedCA})
	return pemCA, httperror.HTTPError{}
}

// GetCAChain -------------
func GetCAChain(backend backend.Storage) (types.PEMCertificateBundle, httperror.HTTPError) {
	// Set the first certificate in the chain to the PKI service's internal
	// intermediate CA certificate
	encodedCA, err := backend.GetSigningCert()
	if err != nil {
		return types.PEMCertificateBundle{}, httperror.StorageReadFail(err.Error())
	}
	decodedCA, err := base64.StdEncoding.DecodeString(encodedCA)
	if err != nil {
		return types.PEMCertificateBundle{}, httperror.DecodeCertError(err.Error())
	}
	caChain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: decodedCA}))

	// Retrieve the rest of the CA chain from the storage backend to an array and
	// loop through each of them, converting to PEM string and appending to the
	// current CA chain
	encodedBundle, err := backend.GetCAChain()
	if err != nil {
		return types.PEMCertificateBundle{}, httperror.StorageReadFail(err.Error())
	}
	for _, encodedCert := range encodedBundle {
		derCert, err := base64.StdEncoding.DecodeString(encodedCert)
		if err != nil {
			return types.PEMCertificateBundle{}, httperror.CAChainProcessError(err.Error())
		}
		pemCert := pem.Block{Type: "CERTIFICATE", Bytes: derCert}
		caChain += string(pem.EncodeToMemory(&pemCert))
	}
	caChainBundle := types.PEMCertificateBundle{
		CertBundle: caChain,
	}

	return caChainBundle, httperror.HTTPError{}
}

// SetCAChain ---------------------
func SetCAChain(pemBundle types.PEMCertificateBundle, backend backend.Storage) httperror.HTTPError {
	var certBundle []string
	// Decode each PEM block from the certificate bundle that was passed in
	// the request, and continue looping until no valid PEM blocks are found
	for pemCert, _ := pem.Decode([]byte(pemBundle.CertBundle)); pemCert != nil; {
		derCert := pemCert.Bytes
		encodedCert := base64.StdEncoding.EncodeToString(derCert)
		certBundle = append(certBundle, encodedCert)
	}
	err := backend.WriteCAChain(certBundle)
	if err != nil {
		return httperror.StorageWriteFail(err.Error())
	}
	return httperror.HTTPError{}
}

// Purge Deletes all certificates from the backend storage certificate store that have been
// expired for longer than the time specified in `daysBuffer`
func Purge(daysBuffer int, backend backend.Storage) httperror.HTTPError {
	deleteList, err := backend.ListExpiredCertificates(daysBuffer)
	if err != nil {
		return httperror.StorageReadFail(err.Error())
	}

	for _, certificate := range deleteList {
		err = backend.DeleteCertificate(certificate)
		if err != nil {
			return httperror.StorageDeleteFail(err.Error())
		}
	}
	revokedCertificates, err := backend.GetRevokedCerts()
	if err != nil {
		return httperror.StorageReadFail(err.Error())
	}

	return CreateCRL(revokedCertificates, backend)
}

// GetCRL -------------------------
func GetCRL(backend backend.Storage) ([]byte, httperror.HTTPError) {
	encodedCRL, err := backend.GetCRL()
	if err != nil {
		return nil, httperror.StorageReadFail(err.Error())
	}
	decodedCRL, err := base64.StdEncoding.DecodeString(encodedCRL)
	if err != nil {
		return nil, httperror.DecodeCRLError(err.Error())
	}
	return decodedCRL, httperror.HTTPError{}
}

/********************************************
TODO:
func OSCPRespHandler(w http.ResponseWriter, r *http.Request) {

}
******************************************/
