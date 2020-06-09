package backend

import (
	"math/big"
	"time"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// StorageBackend -----------------------------------
type StorageBackend interface {
	CreateCertificate(certificateData types.CreateCertificateData) error
	ListCertificates() ([]*big.Int, error)
	GetCertificate(serialNumber *big.Int) (string, error)
	RevokeCertificate(serialNumber *big.Int, reasonCode int, revocationDate time.Time) error
	CreateTemplate(template types.Template) error
	ListTemplates() ([]string, error)
	GetTemplate(templateName string) (types.Template, error)
	DeleteTemplate(templateName string) error
	WriteSigningCert(encodedCert string) error
	GetSigningCert() (string, error)
	WriteSigningKey(encodedKey string) error
	GetSigningKey() (string, error)
	WriteCRL(encodedCRL string) error
	GetCRL() (string, error)
	WriteCAChain(pemBundle []string) error
	GetCAChain() ([]string, error)
	GetRevokedCerts() ([]types.RevokedCertificate, error)

	GetAccessControl() Access
}
