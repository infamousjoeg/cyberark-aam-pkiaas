package vault

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

func getCertificateSecretPath(serialNumber string) string {
	return rootPath() + "/certificates/" + serialNumber
}

func getCertificatesSecretPath() string {
	return rootPath() + "/certificates"
}

func getCertificate(c StorageBackend, serialNumber *big.Int) (types.CreateCertificateData, error) {
	certificate := &types.CreateCertificateData{}

	secretPath := getCertificateSecretPath(serialNumber.String())
	content, err := readSecretAndGetContent(c.client, secretPath, true)
	if err != nil {
		return *certificate, fmt.Errorf("Failed to retrieve certificate with serial number '%s'. %s", serialNumber.String(), err)
	}

	err = json.Unmarshal([]byte(content), certificate)
	if err != nil {
		return *certificate, fmt.Errorf("Failed to unmarshal cert struct into json with serial number '%s'. %s", serialNumber.String(), err)
	}

	return *certificate, err
}

func writeCertificate(c StorageBackend, cert types.CreateCertificateData) error {
	secretPath := getCertificateSecretPath(cert.SerialNumber)
	certJSON, err := json.Marshal(cert)
	if err != nil {
		return fmt.Errorf("Failed to marshal cert struct into json. %s", err)
	}

	return writeSecretContent(c.client, secretPath, true, string(certJSON))
}

// CreateCertificate ...
func (c StorageBackend) CreateCertificate(cert types.CreateCertificateData) error {
	secretPath := getCertificateSecretPath(cert.SerialNumber)
	_, err := readSecretAndGetContent(c.client, secretPath, false)
	if err == nil {
		return fmt.Errorf("Certificate '%s' already exists", cert.SerialNumber)
	}

	return writeCertificate(c, cert)
}

// ListCertificates ...
func (c StorageBackend) ListCertificates() ([]*big.Int, error) {
	var certficateSerialNumbers []*big.Int
	secretPath := getCertificatesSecretPath()
	certs, err := listKVs(c.client, secretPath)
	if err != nil {
		return certficateSerialNumbers, fmt.Errorf("Failed to list certificates. %s", err)
	}

	for _, cert := range certs {
		serialNumber, ok := new(big.Int).SetString(cert, 10)
		if !ok {
			return certficateSerialNumbers, fmt.Errorf("Failed to cast serial number '%s' into type big.Int", cert)
		}
		certficateSerialNumbers = append(certficateSerialNumbers, serialNumber)
	}

	return certficateSerialNumbers, nil
}

// ListExpiredCertificates List all certificates that are currenty expired
func (c StorageBackend) ListExpiredCertificates(dayBuffer int) ([]*big.Int, error) {
	// TODO: thinking about how to implement this function
	var certficateSerialNumbers []*big.Int

	return certficateSerialNumbers, nil
}

// GetCertificate ...
func (c StorageBackend) GetCertificate(serialNumber *big.Int) (string, error) {
	cert, err := getCertificate(c, serialNumber)
	if err != nil {
		return "", err
	}
	return cert.Certificate, err
}

// DeleteCertificate ...
func (c StorageBackend) DeleteCertificate(serialNumber *big.Int) error {
	secretPath := getCertificateSecretPath(serialNumber.String())
	_, err := c.client.Logical().Delete(secretPath)
	return err
}

// RevokeCertificate ...
func (c StorageBackend) RevokeCertificate(serialNumber *big.Int, reasonCode int, revocationDate time.Time) error {
	cert, err := getCertificate(c, serialNumber)
	if err != nil {
		return fmt.Errorf("Failed to revoked certificate with serial number '%s'. %s", serialNumber.String(), err)
	}

	cert.Revoked = true
	cert.RevocationReasonCode = reasonCode
	cert.RevocationDate = fmt.Sprintf("%v", revocationDate.Unix())
	cert.InternalState = "revoked"

	return writeCertificate(c, cert)
}

// GetRevokedCerts ...
func (c StorageBackend) GetRevokedCerts() ([]types.RevokedCertificate, error) {
	// TODO: thinking about how to implement this function
	var revokedCerts []types.RevokedCertificate

	return revokedCerts, nil
}

// CertificateRevoked Return the types.RevokedCertifcate repersented by the certificate
// If the certificate is not revoked, and empty types.RevokedCertificate is returned
func (c StorageBackend) CertificateRevoked(serialNumber *big.Int) (types.RevokedCertificate, error) {
	var revokedCert types.RevokedCertificate
	cert, err := getCertificate(c, serialNumber)
	if err != nil {
		return revokedCert, err
	}
	if !cert.Revoked {
		return revokedCert, nil
	}

	// get time.Time from revocation date which is a string of epoch
	revocationDateInt, err := strconv.Atoi(cert.RevocationDate)
	if err != nil {
		return revokedCert, fmt.Errorf("Failed to cast RevocationDate '%s' into an int", cert.RevocationDate)
	}
	dateTime := time.Unix(int64(revocationDateInt), 0)

	return types.RevokedCertificate{
		SerialNumber:   cert.SerialNumber,
		ReasonCode:     cert.RevocationReasonCode,
		RevocationDate: dateTime,
	}, nil
}
