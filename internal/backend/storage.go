package backend

import (
	"math/big"
	"time"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// Storage -----------------------------------
// Interface that defines the methods and associated
// access control getter for a backend system's Storage
// objects
type Storage interface {
	InitConfig() error
	CreateCertificate(certificateData types.CreateCertificateData) error
	ListCertificates() ([]*big.Int, error)
	GetCertificate(serialNumber *big.Int) (string, error)
	DeleteCertificate(serialNumber *big.Int) error
	RevokeCertificate(serialNumber *big.Int, reasonCode int, revocationDate time.Time) error
	CreateTemplate(template types.Template) error
	ListTemplates() ([]string, error)
	GetTemplate(templateName string) (types.Template, error)
	DeleteTemplate(templateName string) error
	CreateSSHTemplate(template types.SSHTemplate) error
	ListSSHTemplates() ([]string, error)
	GetSSHTemplate(templateName string) (types.SSHTemplate, error)
	DeleteSSHTemplate(templateName string) error
	WriteSigningCert(encodedCert string) error
	GetSigningCert() (string, error)
	WriteSigningKey(encodedKey string) error
	GetSigningKey() (string, error)
	WriteCRL(encodedCRL string) error
	GetCRL() (string, error)
	WriteCAChain(pemBundle []string) error
	GetCAChain() ([]string, error)
	ListExpiredCertificates(int) ([]*big.Int, error)
	GetRevokedCerts() ([]types.RevokedCertificate, error)
	CertificateRevoked(serialNumber *big.Int) (types.RevokedCertificate, error)

	GetAccessControl() Access
}
