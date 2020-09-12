package httperror

import (
	"encoding/json"
	"net/http"
	"runtime"
	"strings"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/pkg/log"
)

// HTTPError ------
type HTTPError struct {
	ErrorCode    string `json:"errorCode"`
	ErrorMessage string `json:"errorMessage"`
	HTTPResponse int    `json:"statusCode"`
}

const invalidHeader string = "HTTP Content-Type header - expected application/json"
const invalidAuthn string = "Invalid authentication from header - "

// InvalidContentType ----------
func InvalidContentType() HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "CreateTemplateHandler":
		errorCode = "CPKICT001"
	case "ManageTemplateHandler":
		errorCode = "CPKIMT001"
	case "GenerateIntermediateHandler":
		errorCode = "CPKIGI001"
	case "SetIntermediateCertHandler":
		errorCode = "CPKISI001"
	case "SetCAChainHandler":
		errorCode = "CPKISC001"
	case "SignCertHandler":
		errorCode = "CPKISG001"
	case "CreateCertHandler":
		errorCode = "CPKICC001"
	case "RevokeCertHandler":
		errorCode = "CPKIRC001"
	case "CreateSSHTemplateHandler":
		errorCode = "CSSHCT001"
	case "ManageSSHTemplateHandler":
		errorCode = "CSSHMT001"
	case "CreateSSHCertificateHandler":
		errorCode = "CSSHCC001"
	}
	return HTTPError{
		ErrorCode:    errorCode,
		ErrorMessage: invalidHeader,
		HTTPResponse: http.StatusUnsupportedMediaType,
	}
}

// InvalidAuthn ------------------
func InvalidAuthn(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "CreateTemplateHandler":
		errorCode = "CPKICT002"
	case "GetTemplateHandler":
		errorCode = "CPKIGT001"
	case "ManageTemplateHandler":
		errorCode = "CPKIMT002"
	case "DeleteTemplateHandler":
		errorCode = "CPKIDT001"
	case "ListTemplatesHandler":
		errorCode = "CPKILT002"
	case "GenerateIntermediateHandler":
		errorCode = "CPKIGI002"
	case "SetIntermediateCertHandler":
		errorCode = "CPKISI002"
	case "SetCAChainHandler":
		errorCode = "CPKISC002"
	case "PurgeHandler":
		errorCode = "CPKIPU001"
	case "PurgeCRLHandler":
		errorCode = "CPKIPC001"
	case "SignCertHandler":
		errorCode = "CPKISG002"
	case "CreateCertHandler":
		errorCode = "CPKICC002"
	case "GetCertHandler":
		errorCode = "CPKICE001"
	case "ListCertsHandler":
		errorCode = "CPKILC001"
	case "RevokeCertHandler":
		errorCode = "CPKIRC002"
	case "CreateSSHTemplateHandler":
		errorCode = "CSSHCT002"
	case "GetSSHTemplateHandler":
		errorCode = "CSSHGT001"
	case "ListSSHTemplatesHandler":
		errorCode = "CSSHLT001"
	case "ManageSSHTemplateHandler":
		errorCode = "CSSHMT003"
	case "DeleteSSHTemplateHandler":
		errorCode = "CSSHDT001"
	case "CreateSSHCertificateHandler":
		errorCode = "CSSHCC002"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: invalidAuthn + err,
		HTTPResponse: http.StatusUnauthorized,
	}
}

// InvalidAuthz -----------------
func InvalidAuthz(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "CreateTemplateHandler":
		errorCode = "CPKICT003"
	case "GetTemplateHandler":
		errorCode = "CPKIGT002"
	case "ManageTemplateHandler":
		errorCode = "CPKIMT004"
	case "DeleteTemplateHandler":
		errorCode = "CPKIDT002"
	case "ListTemplatesHandler":
		errorCode = "CPKILT002"
	case "GenerateIntermediateHandler":
		errorCode = "CPKIGI003"
	case "SetIntermediateCertHandler":
		errorCode = "CPKISI003"
	case "SetCAChainHandler":
		errorCode = "CPKISC003"
	case "PurgeHandler":
		errorCode = "CPKIPU002"
	case "PurgeCRLHandler":
		errorCode = "CPKIPC002"
	case "SignCertHandler":
		errorCode = "CPKISG004"
	case "CreateCertHandler":
		errorCode = "CPKICC004"
	case "RevokeCertHandler":
		errorCode = "CPKIRC004"
	case "CreateSSHTemplateHandler":
		errorCode = "CSSHCT003"
	case "GetSSHTemplateHandler":
		errorCode = "CSSHGT002"
	case "ListSSHTemplatesHandler":
		errorCode = "CSSHLT002"
	case "ManageSSHTemplateHandler":
		errorCode = "CSSHMT004"
	case "DeleteSSHTemplateHandler":
		errorCode = "CSSHDT002"
	case "CreateSSHCertificateHandler":
		errorCode = "CSSHCC004"
	}

	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Not authorized to access requested resource - " + err,
		HTTPResponse: http.StatusForbidden,
	}
}

// RequestDecodeFail --------------------
func RequestDecodeFail(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "CreateTemplateHandler":
		errorCode = "CPKICT004"
	case "ManageTemplateHandler":
		errorCode = "CPKIMT003"
	case "GenerateIntermediateHandler":
		errorCode = "CPKIGI004"
	case "SetIntermediateCertHandler":
		errorCode = "CPKISI004"
	case "SetCAChainHandler":
		errorCode = "CPKISC004"
	case "SignCertHandler":
		errorCode = "CPKIRC003"
	case "CreateCertHandler":
		errorCode = "CPKIRC003"
	case "RevokeCertHandler":
		errorCode = "CPKIRC003"
	case "CreateSSHTemplateHandler":
		errorCode = "CSSHCT002"
	case "CreateSSHCertificateHandler":
		errorCode = "CSSHCC003"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Failed to decode request JSON data - " + err,
		HTTPResponse: http.StatusBadRequest,
	}
}

// InvalidKeyAlgo -----------------
func InvalidKeyAlgo(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "CreateTemplate":
		errorCode = "CPKICT005"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Invalid key algorithm or size - " + err,
		HTTPResponse: http.StatusBadRequest,
	}
}

// InvalidKeyUsage -------------
func InvalidKeyUsage(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "CreateTemplate":
		errorCode = "CPKICT006"
	case "SignCert":
		errorCode = "CPKISG010"
	case "CreateCert":
		errorCode = "CPKICC007"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error validating key usages - " + err,
		HTTPResponse: http.StatusBadRequest,
	}
}

// InvalidExtKeyUsage -----------------
func InvalidExtKeyUsage(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "CreateTemplate":
		errorCode = "CPKICT007"
	case "SignCert":
		errorCode = "CPKISG011"
	case "CreateCert":
		errorCode = "CPKICC008"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error validating extended key usages - " + err,
		HTTPResponse: http.StatusBadRequest,
	}
}

// InvalidPolicyID -----------
func InvalidPolicyID(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "CreateTemplate":
		errorCode = "CPKICT008"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error validating policy identifiers - " + err,
		HTTPResponse: http.StatusBadRequest,
	}
}

// StorageWriteFail --------------
func StorageWriteFail(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "CreateTemplate":
		errorCode = "CPKICT009"
	case "SetCAChain":
		errorCode = "CPKISC005"
	case "CreateSSHTemplate":
		errorCode = "CSSHCT008"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error writing new resource to the storage backend - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// StorageReadFail ---------------------
func StorageReadFail(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "GetTemplate":
		errorCode = "CPKIGT003"
	case "ListTemplates":
		errorCode = "CPKILT003"
	case "GetCA":
		errorCode = "CPKICA01"
	case "GetCRL":
		errorCode = "CPKICR001"
	case "GetCert":
		errorCode = "CPKICE003"
	case "ListCerts":
		errorCode = "CPKILC002"
	case "RevokeCert":
		errorCode = "CPKIRC008"
	case "GetSSHTemplate":
		errorCode = "CSSHGT003"
	case "ListSSHTemplates":
		errorCode = "CSSHLT003"
	case "CreateSSHCertificate":
		errorCode = "CSSHCC006"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error reading resource from storage backend - " + err,
		HTTPResponse: http.StatusNotFound,
	}
}

// ResponseEncodeError -----------
func ResponseEncodeError(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "GetTemplateHandler":
		errorCode = "CPKIGT004"
	case "ListTemplatesHandler":
		errorCode = "CPKILT004"
	case "GenerateIntermediateHandler":
		errorCode = "CPKIGI017"
	case "GetCAChainHandler":
		errorCode = "CPKIGC005"
	case "GetCertHandler":
		errorCode = "CPKICE005"
	case "ListCertsHandler":
		errorCode = "CPKILC004"
	case "ListSSHTemplatesHandler":
		errorCode = "CSSHLT004"
	case "CreateSSHCertificateHandler":
		errorCode = "CSSHCC018"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error encoding response data - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// ResponseWriteError -----------
func ResponseWriteError(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "GetCAHandler":
		errorCode = "CPKICA003"
	case "GetCRLHandler":
		errorCode = "CPKICR003"
	case "SignCertHandler":
		errorCode = "CPKICR016"
	case "CreateCertHandler":
		errorCode = "CPKICC016"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error writing HTTP response - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// StorageDeleteFail -----------
func StorageDeleteFail(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "DeleteTemplate":
		errorCode = "CPKIDT003"
	case "DeleteSSHTemplate":
		errorCode = "CSSHDT003"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error deleting template from backend - " + err,
		HTTPResponse: http.StatusNotFound,
	}
}

// KeygenError ---------
func KeygenError(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "GenerateIntermediate":
		errorCode = "CPKIGI005"
	case "CreateCert":
		errorCode = "CPKICC011"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error generating private keys - " + err,
		HTTPResponse: http.StatusBadRequest,
	}
}

// ProcessSubjectError ---------
func ProcessSubjectError(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "GenerateIntermediate":
		errorCode = "CPKIGI006"
	case "SignCert":
		errorCode = "CPKISG008"
	case "CreateCert":
		errorCode = "CPKICC006"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error processing certificate subject - " + err,
		HTTPResponse: http.StatusBadRequest,
	}
}

// ProcessSANError ---------
func ProcessSANError(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "GenerateIntermediate":
		errorCode = "CPKIGI007"
	case "CreateCert":
		errorCode = "CPKICC009"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error processing SANs - " + err,
		HTTPResponse: http.StatusBadRequest,
	}
}

// InvalidSAN --------
func InvalidSAN(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "GenerateIntermediate":
		errorCode = "CPKISG012"
	case "CreateCert":
		errorCode = "CPKICC010"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Subject Alternate Name validation failed - " + err,
		HTTPResponse: http.StatusBadRequest,
	}
}

// BasicConstraintError ----------
func BasicConstraintError(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "GenerateIntermediate":
		errorCode = "CPKIGI008"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Unable to marshal CA basic constraints to ASN.1 format - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// MarshalKeyUsageError -----------
func MarshalKeyUsageError(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "GenerateIntermediate":
		errorCode = "CPKIGI009"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Unable to marshal CA key usages to ASN.1 format - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// BadSigAlgo -------------
func BadSigAlgo(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "GenerateIntermediate":
		errorCode = "CPKIGI010"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "No matching signature algorithm found in requested template - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// GenerateCSRFail -------
func GenerateCSRFail(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "GenerateIntermediate":
		errorCode = "CPKIGI011"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error while generating new CSR - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// GenerateSerialFail ----------
func GenerateSerialFail(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "GenerateIntermediate":
		errorCode = "CPKIGI012"
	case "CreateSSHCertificate":
		errorCode = "CSSHCC013"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error generating serial number - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// GenerateSelfSignFail ---------
func GenerateSelfSignFail(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "GenerateIntermediate":
		errorCode = "CPKIGI013"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error while generating new self signed cert - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// CertWriteFail ---------
func CertWriteFail(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "GenerateIntermediate":
		errorCode = "CPKIGI014"
	case "SetIntermediateCertificate":
		errorCode = "CPKISI013"
	case "SignCert":
		errorCode = "CPKISG015"
	case "CreateCert":
		errorCode = "CPKICC015"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error writing certificate to backend storage - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// ECDSAKeyError -------------
func ECDSAKeyError(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "GenerateIntermediate":
		errorCode = "CPKIGI015"
	case "CreateCert":
		errorCode = "CPKICC013"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error marshaling ECDSA private key - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// SigningKeyWriteFail ---------
func SigningKeyWriteFail(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "GenerateIntermediate":
		errorCode = "CPKIGI016"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error while writing signing key to storage backend - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// SigningKeyReadFail -----------
func SigningKeyReadFail(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "SetIntermediateCertificate":
		errorCode = "CPKISI008"
	case "RevokeCert":
		errorCode = "CPKIRC010"
	case "CreateSSHCertificate":
		errorCode = "CSSHCC005"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error reading signing key from storage backend - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// InvalidCertificateFormat --------
func InvalidCertificateFormat() HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "SetIntermediateCertificate":
		errorCode = "CPKISI005"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Certificate from request is not in valid PEM format",
		HTTPResponse: http.StatusBadRequest,
	}
}

// ParseCertificateError -----------
func ParseCertificateError(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "SetIntermediateCertificate":
		errorCode = "CPKISI006"
	case "RevokeCert":
		errorCode = "CPKIRC014"
	case "CreateSSHCertificate":
		errorCode = "CSSHCC015"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error parsing X.509 certificate - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// ParseCSRError -----------
func ParseCSRError(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "SignCert":
		errorCode = "CPKISG006"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error parsing the certificate request - ",
		HTTPResponse: http.StatusInternalServerError,
	}
}

// InvalidPEM -----------
func InvalidPEM() HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "SignCert":
		errorCode = "CPKISG005"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "No valid PEM block was found in request",
		HTTPResponse: http.StatusInternalServerError,
	}
}

// CertificatePublicKeyError ----
func CertificatePublicKeyError(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "SetIntermediateCertificate":
		errorCode = "CPKISI007"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error parsing the public key from certificate - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// DecodeCertError ------------
func DecodeCertError(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "GetCA":
		errorCode = "CPKICA002"
	case "GetCAChain":
		errorCode = "CPKIGC002"
	case "GetCert":
		errorCode = "CPKICE004"
	case "RevokeCert":
		errorCode = "CPKIRC013"
	case "CreateSSHCertificate":
		errorCode = "CSSHCC014"

	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error decoding certificate from base64 - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// DecodeSigningKeyError -------------
func DecodeSigningKeyError(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "SetIntermediateCertificate":
		errorCode = "CPKISI009"
	case "CreateSSHCertificate":
		errorCode = "CSSHCC012"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error decoding signing key from base64 - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// DecodeCRLError -----------
func DecodeCRLError(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "GetCRL":
		errorCode = "CPKICR002"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error decoding the CRL from base64 - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// ParseSigningKeyError ------------
func ParseSigningKeyError(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "SetIntermediateCertificate":
		errorCode = "CPKISI010"
	case "RevokeCert":
		errorCode = "CPKIRC011"
	case "CreateSSHCertificate":
		errorCode = "CSSHCC019"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error parsing the signing key - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// ParsePublicKeyError --------
func ParsePublicKeyError(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "SetIntermediateCertificate":
		errorCode = "CPKISI011"
	case "CreateSSHCertificate":
		errorCode = "CSSHCC011"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error parsing the public key from the signing key - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// PublicKeyMismatch ----------
func PublicKeyMismatch() HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "SetIntermediateCertificate":
		errorCode = "CPKISI012"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Certificate public key does not match the signing key",
		HTTPResponse: http.StatusBadRequest,
	}
}

// CAChainProcessError ---------
func CAChainProcessError(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "GetCAChain":
		errorCode = "CPKIGC004"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error processing CA chain - " + err,
		HTTPResponse: http.StatusBadRequest,
	}
}

// CertificateParameterFail --------
func CertificateParameterFail(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "SignCert":
		errorCode = "CPKISG007"
	case "CreateCert":
		errorCode = "CPKICC005"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Unable to set required parameters - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// TemplateSubjectMismatch -----------
func TemplateSubjectMismatch() HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "SignCert":
		errorCode = "CPKISG009"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "CSR Subject does not match the Subject set in the template",
		HTTPResponse: http.StatusBadRequest,
	}
}

// CreateCertificateFail ---------
func CreateCertificateFail(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "SignCert":
		errorCode = "CPKISG013"
	case "CreateCert":
		errorCode = "CPKICC012"
	case "CreateSSHCertificate":
		errorCode = "CSSHCC017"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error while creating certificate - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// SerialNumberConversionError ------
func SerialNumberConversionError(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "SignCert":
		errorCode = "CPKISG014"
	case "CreateCert":
		errorCode = "CPKICC014"
	case "GetCert":
		errorCode = "CPKICE002"
	case "ListCerts":
		errorCode = "CPKILC003"
	case "RevokeCert":
		errorCode = "CPKIRC006"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error while converting serial number format - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// ParseReasonFail ------------
func ParseReasonFail(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "RevokeCert":
		errorCode = "CPKIRC005"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error parsing revocation reason - " + err,
		HTTPResponse: http.StatusBadRequest,
	}
}

// RevocationFail ---------------
func RevocationFail(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "RevokeCert":
		errorCode = "CPKIRC007"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Certificate revocation failed on backend - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// CreateCRLFail -----------------
func CreateCRLFail(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "RevokeCert":
		errorCode = "CPKIRC015"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error while creating new CRL - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// WriteCRLFail -----------
func WriteCRLFail(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "RevokeCert":
		errorCode = "CPKIRC016"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Error writing new CRL to storage backend - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// InvalidCN -----------
func InvalidCN(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "SignCert":
		errorCode = "CPKISG016"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Invalid Common Name requested for certificate - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// SSHInvalidHost ---------
func SSHInvalidHost(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "CreateSSHTemplate":
		errorCode = "CSSHCT005"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "The requested SSH hostname is invalid - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// SSHInvalidPrincipal ---------
func SSHInvalidPrincipal(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "CreateSSHTemplate":
		errorCode = "CSSHCT006"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "The requested SSH principal is invalid - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// SSHInvalidCertType ---------
func SSHInvalidCertType() HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "CreateSSHTemplate":
		errorCode = "CSSHCT007"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Invalid certificate type, valid options are Host or User",
		HTTPResponse: http.StatusBadRequest,
	}
}

// SSHForbiddenPrincipal ---------
func SSHForbiddenPrincipal(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "CreateSSHCertificate":
		errorCode = "CSSHCC007"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "The requested SSH principal is forbidden - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// SSHForbiddenHost ---------
func SSHForbiddenHost(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "CreateSSHCertificate":
		errorCode = "CSSHCC008"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "The requested SSH hostname is forbidden - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// SSHForbiddenCriticalOption ---------
func SSHForbiddenCriticalOption(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "CreateSSHCertificate":
		errorCode = "CSSHCC009"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "The requested SSH critical option is forbidden - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// SSHForbiddenExtension ---------
func SSHForbiddenExtension(err string) HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "CreateSSHCertificate":
		errorCode = "CSSHCC010"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "The requested SSH extension is forbidden - " + err,
		HTTPResponse: http.StatusInternalServerError,
	}
}

// InvalidValidityPeriod ---------
func InvalidValidityPeriod() HTTPError {
	var errorCode string
	switch getCallerFunctionName() {
	case "CreateSSHCertificate":
		errorCode = "CSSHCC016"
	}
	return HTTPError{ErrorCode: errorCode,
		ErrorMessage: "Requested certificate validity period is greater than the CA validity period",
		HTTPResponse: http.StatusInternalServerError,
	}
}

// JSON ------------
func (httpErr HTTPError) JSON() string {
	log.Error("%s %s. Status code: %v", httpErr.ErrorCode, httpErr.ErrorMessage, httpErr.HTTPResponse)
	json, _ := json.Marshal(httpErr)
	return string(json)
}

func getCallerFunctionName() string {
	stackAddr := make([]uintptr, 1)
	runtime.Callers(3, stackAddr)
	caller := runtime.FuncForPC(stackAddr[0] - 1)
	parts := strings.Split(caller.Name(), ".")
	return parts[len(parts)-1]
}
