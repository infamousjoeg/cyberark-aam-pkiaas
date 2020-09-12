package dummy

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/pki"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// Dummy ------------------------
type Dummy struct {
	Access AccessControl
}

var dummySubject types.SubjectFields = types.SubjectFields{
	Organization: "CyberArk",
	Province:     "MA",
}
var dummyTemplate types.Template = types.Template{
	TemplateName:     "TestTemplate",
	KeyAlgo:          "RSA",
	KeyBits:          "2048",
	StoreCertificate: true,
	MaxTTL:           115200,
	KeyUsages:        []string{"keyEncipherment", "digitalSignature", "decipherOnly"},
	ExtKeyUsages:     []string{"serverAuth", "clientAuth", "codeSigning", "emailProtection", "ipsecEndSystem", "ipsecTunnel", "ipsecUser", "timeStamping", "OCSPSigning", "msSGC", "nsSGC", "msCodeCom"},
}

var dummySSHTemplate types.SSHTemplate = types.SSHTemplate{
	TemplateName: "TestSSHTemplate",
	MaxTTL:       3600,
	CertType:     "User",
}

// GetCertificate ----------------------------------------------------------------
// Finds matching certificate matching serial number in DAP and returns it; Sends appropriate
// error message as necessary
func (d Dummy) GetCertificate(serialNumber *big.Int) (string, error) {
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

// GetCAChain ------------------------------------------------------------------
func (d Dummy) GetCAChain() ([]string, error) {
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

// ListCertificates ----------------------------------------------------------
func (d Dummy) ListCertificates() ([]*big.Int, error) {
	retVal := big.NewInt(12312313123)
	return []*big.Int{retVal}, nil
}

// GetTemplate ----------------------------------------------------------
func (d Dummy) GetTemplate(templateName string) (types.Template, error) {
	if templateName == "TestTemplate" {
		return dummyTemplate, nil
	}
	return types.Template{}, errors.New("Unable to locate template with template name " + templateName)
}

// CreateTemplate ---------------------------------------------------------
func (d Dummy) CreateTemplate(newTemplate types.Template) error {
	template, err := json.Marshal(newTemplate)
	if err != nil {
		return errors.New("Unable to import newly requested template data")
	}
	fmt.Println(string(template))
	return nil
}

// DeleteTemplate --------------------------------------------------------
func (d Dummy) DeleteTemplate(templateName string) error {
	if templateName == "TestTemplate" {
		fmt.Println("Successfully deleted TestTemplate")
		return nil
	}
	return errors.New("No template matching " + templateName + " was found")
}

// ListTemplates ------------------------------------------------------
func (d Dummy) ListTemplates() ([]string, error) {
	return []string{"Template1", "Template2"}, nil
}

// CreateSSHTemplate Dummy function to simulate creating a new SSH template
// in the storage backend
func (d Dummy) CreateSSHTemplate(newTemplate types.SSHTemplate) error {
	template, err := json.Marshal(newTemplate)
	if err != nil {
		return errors.New("Unable to import newly requested template data")
	}
	fmt.Println(string(template))
	return nil
}

// ListSSHTemplates Dummy function to simulate listing all SSH templates
// currently existing in the storage backend
func (d Dummy) ListSSHTemplates() ([]string, error) {
	return []string{"UserCertAllHosts", "UserCertAllowX11", "HostCert"}, nil
}

// GetSSHTemplate Dummy function to simulate returning a single template object
// from the storage backend
func (d Dummy) GetSSHTemplate(templateName string) (types.SSHTemplate, error) {
	return dummySSHTemplate, nil
}

// DeleteSSHTemplate Dummy function to simulate the deletion of a template object
// from the storage backend
func (d Dummy) DeleteSSHTemplate(templateName string) error {
	if templateName == "TestSSHTemplate" {
		fmt.Println("Successfully deleted TestTemplate")
		return nil
	}
	return errors.New("No template matching " + templateName + " was found")
}

// GetSigningCert -------------------------------------------------------
func (d Dummy) GetSigningCert() (string, error) {
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

// GetSigningKey --------------------------------------------------------
func (d Dummy) GetSigningKey() (string, error) {
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

// GetRevokedCerts ------------------------------------------------------
func (d Dummy) GetRevokedCerts() ([]types.RevokedCertificate, error) {
	serialNumber := new(big.Int)
	serialNumber.SetString("10351605685901192", 10)
	return []types.RevokedCertificate{
		{
			SerialNumber:   serialNumber.String(),
			RevocationDate: time.Now(),
			ReasonCode:     0,
		}}, nil
}

// RevokeCertificate -------------------------------------------------------------
func (d Dummy) RevokeCertificate(serialNumber *big.Int, reasonCode int, revocationDate time.Time) error {
	fmt.Println("Revoked Cert\nSerial Number: " + serialNumber.String() + "\nReason Code: " + string(reasonCode) + "\nRevocation Date: " + revocationDate.String())
	return nil
}

// WriteCRL ----------------------------------------------------------------
func (d Dummy) WriteCRL(newCRL string) error {
	fmt.Println(newCRL)
	return nil
}

// GetCRL ---------------------------------------------------------------
func (d Dummy) GetCRL() (string, error) {
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

// WriteSigningCert --------------------------------------------------------
func (d Dummy) WriteSigningCert(newCert string) error {
	fmt.Println(newCert)
	return nil
}

// WriteSigningKey ---------------------------------------------------------
func (d Dummy) WriteSigningKey(newKey string) error {
	fmt.Println(newKey)
	return nil
}

// WriteCAChain ------------------------------------------------------------
func (d Dummy) WriteCAChain(certBundle []string) error {
	return nil
}

// DeleteCertificate -----------------------------------------------------
func (d Dummy) DeleteCertificate(serialNumber *big.Int) error {
	return nil
}

// CreateCertificate --------------------------------------------------
func (d Dummy) CreateCertificate(certificateData types.CreateCertificateData) error {
	return nil
}

// GetAccessControl ----------------------------------
func (d Dummy) GetAccessControl() backend.Access {
	return backend.Access(d.Access)
}

// CertificateRevoked ----------------------------------
func (d Dummy) CertificateRevoked(serialNumber *big.Int) (types.RevokedCertificate, error) {
	return types.RevokedCertificate{
		SerialNumber:   "someSerialNumber",
		ReasonCode:     1,
		RevocationDate: time.Now(),
	}, nil
}

// InitConfig ------
func (d Dummy) InitConfig() error {
	return nil
}
