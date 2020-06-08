package dummy

import (
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/pki"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// Dummy ------------------------
type Dummy struct {
}

var dummySubject types.SubjectFields = types.SubjectFields{
	Organization: "CyberArk",
	Province:     "MA",
}
var dummyTemplate types.Template = types.Template{
	TemplateName: "TestTemplate",
	Subject:      dummySubject,
	KeyAlgo:      "RSA",
	KeyBits:      "2048",
	MaxTTL:       115200,
	KeyUsages:    []string{"keyEncipherment", "digitalSignature", "decipherOnly"},
	ExtKeyUsages: []string{"serverAuth", "clientAuth", "codeSigning", "emailProtection", "ipsecEndSystem", "ipsecTunnel", "ipsecUser", "timeStamping", "OCSPSigning", "msSGC", "nsSGC", "msCodeCom"},
}

// GetCertFromDAP ----------------------------------------------------------------
// Finds matching certificate matching serial number in DAP and returns it; Sends appropriate
// error message as necessary
func GetCertFromDAP(serialNumber *big.Int) (string, error) {
	if serialNumber.String() == "10351605685901192" {
		certificate := `MIIDjTCCAnWgAwIBAgIUMC64a4mBmJHhpYBLknrCO8fTcQwwDQYJKoZIhvcNAQELBQAwVjELMAkG
A1UEBhMCVVMxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMg
UHR5IEx0ZDEPMA0GA1UEAwwGQ0FDZXJ0MB4XDTIwMDYwMjAzNTY0NloXDTI0MDcxMTAzNTY0Nlow
VjELMAkGA1UEBhMCVVMxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdp
ZGdpdHMgUHR5IEx0ZDEPMA0GA1UEAwwGQ0FDZXJ0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA5W1pow1OKlb5OSiQsXb2aGkvxeQSrKQ62BUWM+b72SRQSJi4WeYKv+KKqx/sC75DItbW
OwC7mKEOjAIlRlTfruc/Bv8Oxx0vt+DywaBdL/FHFQW+rXETtu2oLixBogr11poeg7Qo7cnS3o2m
RN6ptUlVfnH3XZ0fD+YyriyLmymShoe+YKxQvCS3I28XHOt3X36GC0moQikZGUuCcJvckXuz0bVb
vncq3qdLYEGPxGNsQxLaF4g5uhs4SXYsMATIpNiA+xw8UmfOuANXIaGIiIbavXRxKG7ckw2PJWVi
8ouu21lYMESyb1RjfjmQ6UbyX/k36HrdLrjGM7AB3uUAswIDAQABo1MwUTAdBgNVHQ4EFgQUBm1q
fMA1i6GLYrZZ0Nu9ghN94mYwHwYDVR0jBBgwFoAUBm1qfMA1i6GLYrZZ0Nu9ghN94mYwDwYDVR0T
AQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAbmKMms8XjQ9EeV3MVQd7YLdWJntFrHUVI93r
tf5BcEsXp5PwvY5MVB2zjPChvNcsIlmYkkyCJUO/zJR4xjlohNTWkrCnSlSpZx1dcUOmJy5paaW1
+4TuJaca5Go2sfNkLJp9EcRQvZ1QOxOg5rfjcW9tCZ4iso664JWVHj310teFw0PFYHvjfAcSn8rB
jn9cBqplHlxB0c09IFccUg1Rv1ppFeaz25fx2h1H3fZ8JIdD4ScgN5qEHTCyN6XTwu6ByuqLyhqD
SYiaan+03TI5KlBqIzWwY9Ww9HVZww+NFrnX9IrvXcgYkY1ZyxUZNmpOmOWWf8QBc8IIhNucxhvT
Iw==`
		return certificate, nil
	}

	octetSerialNumber, _ := pki.ConvertSerialIntToOctetString(serialNumber)
	return "", errors.New("No certificate with requested serial number :" + octetSerialNumber + " was found")
}

// GetCAChainFromDAP ------------------------------------------------------------------
func GetCAChainFromDAP() ([]string, error) {
	chain := []string{}
	chain = append(chain, `MIIDjTCCAnWgAwIBAgIUMC64a4mBmJHhpYBLknrCO8fTcQwwDQYJKoZIhvcNAQELBQAwVjELMAkG
A1UEBhMCVVMxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMg
UHR5IEx0ZDEPMA0GA1UEAwwGQ0FDZXJ0MB4XDTIwMDYwMjAzNTY0NloXDTI0MDcxMTAzNTY0Nlow
VjELMAkGA1UEBhMCVVMxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdp
ZGdpdHMgUHR5IEx0ZDEPMA0GA1UEAwwGQ0FDZXJ0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA5W1pow1OKlb5OSiQsXb2aGkvxeQSrKQ62BUWM+b72SRQSJi4WeYKv+KKqx/sC75DItbW
OwC7mKEOjAIlRlTfruc/Bv8Oxx0vt+DywaBdL/FHFQW+rXETtu2oLixBogr11poeg7Qo7cnS3o2m
RN6ptUlVfnH3XZ0fD+YyriyLmymShoe+YKxQvCS3I28XHOt3X36GC0moQikZGUuCcJvckXuz0bVb
vncq3qdLYEGPxGNsQxLaF4g5uhs4SXYsMATIpNiA+xw8UmfOuANXIaGIiIbavXRxKG7ckw2PJWVi
8ouu21lYMESyb1RjfjmQ6UbyX/k36HrdLrjGM7AB3uUAswIDAQABo1MwUTAdBgNVHQ4EFgQUBm1q
fMA1i6GLYrZZ0Nu9ghN94mYwHwYDVR0jBBgwFoAUBm1qfMA1i6GLYrZZ0Nu9ghN94mYwDwYDVR0T
AQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAbmKMms8XjQ9EeV3MVQd7YLdWJntFrHUVI93r
tf5BcEsXp5PwvY5MVB2zjPChvNcsIlmYkkyCJUO/zJR4xjlohNTWkrCnSlSpZx1dcUOmJy5paaW1
+4TuJaca5Go2sfNkLJp9EcRQvZ1QOxOg5rfjcW9tCZ4iso664JWVHj310teFw0PFYHvjfAcSn8rB
jn9cBqplHlxB0c09IFccUg1Rv1ppFeaz25fx2h1H3fZ8JIdD4ScgN5qEHTCyN6XTwu6ByuqLyhqD
SYiaan+03TI5KlBqIzWwY9Ww9HVZww+NFrnX9IrvXcgYkY1ZyxUZNmpOmOWWf8QBc8IIhNucxhvT
Iw==`)
	return chain, nil
}

// GetAllCertsFromDAP ----------------------------------------------------------
func GetAllCertsFromDAP() ([]string, error) {
	return []string{"10351605685901192"}, nil
}

// GetTemplateFromDAP ----------------------------------------------------------
func GetTemplateFromDAP(templateName string) (types.Template, error) {
	if templateName == "TestTemplate" {
		return dummyTemplate, nil
	}
	return types.Template{}, errors.New("Unable to locate template with template name " + templateName)
}

// CreateTemplateInDAP ---------------------------------------------------------
func CreateTemplateInDAP(newTemplate types.Template) error {
	template, err := json.Marshal(newTemplate)
	if err != nil {
		return errors.New("Unable to import newly requested template data")
	}
	fmt.Println(string(template))
	return nil
}

// DeleteTemplateFromDAP --------------------------------------------------------
func DeleteTemplateFromDAP(templateName string) error {
	if templateName == "TestTemplate" {
		fmt.Println("Successfully deleted TestTemplate")
		return nil
	}
	return errors.New("No template matching " + templateName + " was found")
}

// GetAllTemplatesFromDAP ------------------------------------------------------
func GetAllTemplatesFromDAP() ([]string, error) {
	return []string{"Template1", "Template2"}, nil
}

// GetSigningCertFromDAP -------------------------------------------------------
func GetSigningCertFromDAP() (string, error) {
	return `MIIDjTCCAnWgAwIBAgIUMC64a4mBmJHhpYBLknrCO8fTcQwwDQYJKoZIhvcNAQELBQAwVjELMAkG
A1UEBhMCVVMxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMg
UHR5IEx0ZDEPMA0GA1UEAwwGQ0FDZXJ0MB4XDTIwMDYwMjAzNTY0NloXDTI0MDcxMTAzNTY0Nlow
VjELMAkGA1UEBhMCVVMxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdp
ZGdpdHMgUHR5IEx0ZDEPMA0GA1UEAwwGQ0FDZXJ0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA5W1pow1OKlb5OSiQsXb2aGkvxeQSrKQ62BUWM+b72SRQSJi4WeYKv+KKqx/sC75DItbW
OwC7mKEOjAIlRlTfruc/Bv8Oxx0vt+DywaBdL/FHFQW+rXETtu2oLixBogr11poeg7Qo7cnS3o2m
RN6ptUlVfnH3XZ0fD+YyriyLmymShoe+YKxQvCS3I28XHOt3X36GC0moQikZGUuCcJvckXuz0bVb
vncq3qdLYEGPxGNsQxLaF4g5uhs4SXYsMATIpNiA+xw8UmfOuANXIaGIiIbavXRxKG7ckw2PJWVi
8ouu21lYMESyb1RjfjmQ6UbyX/k36HrdLrjGM7AB3uUAswIDAQABo1MwUTAdBgNVHQ4EFgQUBm1q
fMA1i6GLYrZZ0Nu9ghN94mYwHwYDVR0jBBgwFoAUBm1qfMA1i6GLYrZZ0Nu9ghN94mYwDwYDVR0T
AQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAbmKMms8XjQ9EeV3MVQd7YLdWJntFrHUVI93r
tf5BcEsXp5PwvY5MVB2zjPChvNcsIlmYkkyCJUO/zJR4xjlohNTWkrCnSlSpZx1dcUOmJy5paaW1
+4TuJaca5Go2sfNkLJp9EcRQvZ1QOxOg5rfjcW9tCZ4iso664JWVHj310teFw0PFYHvjfAcSn8rB
jn9cBqplHlxB0c09IFccUg1Rv1ppFeaz25fx2h1H3fZ8JIdD4ScgN5qEHTCyN6XTwu6ByuqLyhqD
SYiaan+03TI5KlBqIzWwY9Ww9HVZww+NFrnX9IrvXcgYkY1ZyxUZNmpOmOWWf8QBc8IIhNucxhvT
Iw==`, nil
}

// GetSigningKeyFromDAP --------------------------------------------------------
func GetSigningKeyFromDAP() (string, error) {
	signingKey := `MIIEpgIBAAKCAQEA5W1pow1OKlb5OSiQsXb2aGkvxeQSrKQ62BUWM+b72SRQSJi4WeYKv+KKqx/s
C75DItbWOwC7mKEOjAIlRlTfruc/Bv8Oxx0vt+DywaBdL/FHFQW+rXETtu2oLixBogr11poeg7Qo
7cnS3o2mRN6ptUlVfnH3XZ0fD+YyriyLmymShoe+YKxQvCS3I28XHOt3X36GC0moQikZGUuCcJvc
kXuz0bVbvncq3qdLYEGPxGNsQxLaF4g5uhs4SXYsMATIpNiA+xw8UmfOuANXIaGIiIbavXRxKG7c
kw2PJWVi8ouu21lYMESyb1RjfjmQ6UbyX/k36HrdLrjGM7AB3uUAswIDAQABAoIBAQC5XRsaZ+ed
gcO+kK3HFEyls0ar5kfIQLBiYTcdHCSjHhnXbbyUta49tnU/KX13R3PKtDVGWqM2//lW2WzwVCad
k6xypKR173jcYd0A3+YqlBBQReH3FANPqthU5eDpYV2a086ProHbDVNYCK4rupL3K5btoHqxof60
w9Jysv7gjsBkYjezKGSJVh4NjK/nA/in8Bphn+uLOvpxqtgdH4Z9dCQuWVvRBFV67Vhh1o4nBEET
GjxeOts8ewaDb4ojSoEbdudLgM4ZxziiYXGWP1epkoxrK6NmwC32jSKnYqIVkVDmiQKGwP+lrWJ3
VCJvTecNjXeTZhZFp2N8KzDTEIkxAoGBAPe/Qfllib1mUFX6eGWc79UPX6QAzRX1NPF2eJbywKOA
rWu4G7dKUacxKjt9wR59aVpM5ai3jc0+mI/oLTZSEvkf9O9TIAMndyk42Qn34AjhU03ppYXRiKj/
MlHWzOjxkq9q6yEJ9y74Wuqodkfalt3g0QBmY29ZX/2vRjV7XhW9AoGBAO0R7YP52TvdxRrL8vug
tIQ2Vox6FLIx2PwwFs0Ddii/m6JzDg/3kGEX7Sd7d/tSM38zeY4zKfE4CQyfGhM4NMyKgcIgnxau
+HyHbDCGBwNbYb3JELA/TEnhrk8lDJmkNNSVrYktWC/NDCIp8U29eNidusMmoR1YgWsuANw0878v
AoGBANtww/4kqwFhG61cQsI2ZNSCXoOE1iMp43AxMJT7hhgMxQ8RrzMFmBeQW8kAFUttaCC81ftA
QlDWrglhbJKd1gJmBOzq4wMINOsFWHEU5pLXCpOLbbp/Ix4VlLuamDuIphXMjWHhUtl+0ADjoIj6
nAEBvf4tssuRDY5Fbtm2YVq9AoGBAJ9m6I9O1dQ9H6UO8UhkHDyx1KwMAhJ3FfEr3IjpBPANNfaa
6h+uVDQUxG9Bw8EG2n1y/Q6yNEdvaBZGfF/j8Qx/LRR8nru/1nDVFdfipqCJN0VHBqObTA55Ypzw
ynIcSTGPmumbxaoOc1QdY5TkC3eLRuKk/LwgoJSSkB2AtUwdAoGBAOT+kxIeTHGQFh37AAOHJg+5
L3o6zdwSDhIWebpl0OC9D1VnvdqfKjBNIh/89oD1YNbdiYrTfzQxbbDt8Ts5zVaxVpn06/Wk2Vp8
drcJcTzQVTv7zbQ4NMfd8pThaEzOhS0J1Wn3j+rxZOCpHdKmdd2urD4pU4IQGg/O2AIYoftX`
	return signingKey, nil
}

// GetRevokedCertsFromDAP ------------------------------------------------------
func GetRevokedCertsFromDAP() ([]pkix.RevokedCertificate, error) {
	serialNumber := new(big.Int)
	serialNumber.SetString("10351605685901192", 10)
	return []pkix.RevokedCertificate{
		{
			SerialNumber:   serialNumber,
			RevocationTime: time.Now(),
		}}, nil
}

// RevokeCertInDAP -------------------------------------------------------------
func RevokeCertInDAP(serialNumber *big.Int, reasonCode int, revocationDate time.Time) error {
	fmt.Println("Revoked Cert\nSerial Number: " + serialNumber.String() + "\nReason Code: " + string(reasonCode) + "\nRevocation Date: " + revocationDate.String())
	return nil
}

// WriteCRLToDAP ----------------------------------------------------------------
func WriteCRLToDAP(newCRL string) error {
	fmt.Println(newCRL)
	return nil
}

// GetCRLFromDAP ---------------------------------------------------------------
func GetCRLFromDAP() (string, error) {
	crl := `MIIBrzCBmAIBATANBgkqhkiG9w0BAQsFADBWMQswCQYDVQQGEwJVUzETMBEGA1UECAwKU29tZS1T
dGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMQ8wDQYDVQQDDAZDQUNlcnQX
DTIwMDYwMjIwMjUzM1oXDTIwMDcwMjIwMjUzM1qgDjAMMAoGA1UdFAQDAgEBMA0GCSqGSIb3DQEB
CwUAA4IBAQA0MWpQWYy6635JnO1t/hL4vqoYBbOP8cKCSmeskwyTD1URqVAhGA59wZYZXd+QUmy2
P3n18zyHZo4n5ehI5I6HC1Umorosdn1FeQNpdOiuTbtrRBygn9WK0HZjhSqldCJxBLk41NgFBjDL
MekfzKTXEEA+5JqgNb+tTx66F94d/NwSRF4XV2ipc/h62BwpDmcdGZKjMrhy+1bMgs5r0qB/EEja
scJt3WKh+bihg20OBl32Wkd8en6GwyBZY3AJhgLnSaVDetr/r5Ha5ykRloNTR92QtaG33soUc5It
r+wedff4yOk35vKRlq16vYevY9mppefT4mD9lO5ragxrLXw6`
	return crl, nil
}

// WriteSigningCertToDAP --------------------------------------------------------
func WriteSigningCertToDAP(newCert string) error {
	return nil
}

// WriteSigningKeyToDAP ---------------------------------------------------------
func WriteSigningKeyToDAP(newKey string) error {
	return nil
}

// WriteCAChainToDAP ------------------------------------------------------------
func WriteCAChainToDAP(certBundle []string) error {
	return nil
}

// DeleteCertificateFromDAP -----------------------------------------------------
func DeleteCertificateFromDAP(serialNumber *big.Int) error {
	return nil
}
