package conjur

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// CreateCertificate ...
func (c StorageBackend) CreateCertificate(cert types.CreateCertificateData) error {
	variableID := c.getCertificateVariableID(cert.SerialNumber)

	// validate cert does not exists
	_, err := c.client.RetrieveSecret(variableID)
	if err == nil {
		return fmt.Errorf("Certificate '%s' already exists", cert.SerialNumber)
	}
	return c.updateCertificate(cert, c.templates.newCertificate)

}

func (c StorageBackend) updateCertificate(cert types.CreateCertificateData, policyTemplate string) error {
	variableID := c.getCertificateVariableID(cert.SerialNumber)

	// replace template placeholders
	newPolicy := bytes.NewReader([]byte(ReplaceCertificate(cert, policyTemplate)))

	// Load policy to create the variable
	response, err := c.client.LoadPolicy(
		conjurapi.PolicyModePatch,
		c.getCertificatePolicyBranch(),
		newPolicy,
	)

	if err != nil {
		return fmt.Errorf("Failed to load policy for creating certificate. Message '%v'. %s", response, err)
	}

	// Set the Secret value
	// If certificate value is not provided assume we are
	// just updating the certificate variable annotations
	if cert.Certificate != "" {
		err = c.client.AddSecret(variableID, cert.Certificate)
	}
	return err
}

// ListCertificates ...
func (c StorageBackend) ListCertificates() ([]*big.Int, error) {
	filter := &conjurapi.ResourceFilter{
		Kind:   "variable",
		Search: "certificates",
	}

	var certficateSerialNumbers []*big.Int

	// List resources to get templates
	resources, err := ListResources(c.client, filter)
	if err != nil {
		return certficateSerialNumbers, err
	}

	// Parse the template name for all of the template variables
	for _, resource := range resources {
		_, _, id := SplitConjurID(resource)
		parts := strings.Split(id, "/")
		templatesRoot := parts[len(parts)-2]
		if templatesRoot == "certificates" {
			serialNumberString := parts[len(parts)-1]
			// NOTE: I don't really know what the 10 does at then end of the SetString() function
			serialNumber, ok := new(big.Int).SetString(serialNumberString, 10)
			if ok {
				certficateSerialNumbers = append(certficateSerialNumbers, serialNumber)
			} else {
				// If we failed to cast then return an error
				return certficateSerialNumbers, fmt.Errorf("Failed to cast serial number '%s' into type big.Int", serialNumberString)
			}

		}
	}

	return certficateSerialNumbers, err
}

// GetCertificate ...
func (c StorageBackend) GetCertificate(serialNumber *big.Int) (string, error) {
	variableID := c.getCertificateVariableID(serialNumber.String())
	value, err := c.client.RetrieveSecret(variableID)

	if err != nil {
		return "", fmt.Errorf("Failed to retrieve certificate with serial number '%s'. %s", variableID, err)
	}

	return string(value), err
}

// DeleteCertificate ...
func (c StorageBackend) DeleteCertificate(serialNumber *big.Int) error {
	// validate template resource exists
	variableID := c.getCertificateVariableID(serialNumber.String())
	_, err := c.client.RetrieveSecret(variableID)
	if err != nil {
		return fmt.Errorf("Failed to retrieve certificate with serial number '%s'. %s", variableID, err)
	}

	// remove the template resource
	certificate := types.CreateCertificateData{
		SerialNumber: serialNumber.String(),
	}
	deleteCertPolicy := bytes.NewReader([]byte(
		ReplaceCertificate(certificate, c.templates.deleteCertificate)))

	response, err := c.client.LoadPolicy(
		conjurapi.PolicyModePatch,
		c.getCertificatePolicyBranch(),
		deleteCertPolicy,
	)
	if err != nil {
		return fmt.Errorf("Failed to delete template with id '%s'. Message: '%v'. %s", variableID, response, err)
	}

	return err
}

// RevokeCertificate ...
func (c StorageBackend) RevokeCertificate(serialNumber *big.Int, reasonCode int, revocationDate time.Time) error {
	variableID := c.getCertificateVariableID(serialNumber.String())
	_, err := c.client.RetrieveSecret(variableID)

	if err != nil {
		return fmt.Errorf("Failed to revoked certificate with ID '%s'. %s", variableID, err)
	}

	certificateInDap := types.CreateCertificateData{
		SerialNumber:         serialNumber.String(),
		Revoked:              true,
		RevocationDate:       fmt.Sprintf("%v", revocationDate.Unix()),
		RevocationReasonCode: reasonCode,
		InternalState:        "revoked",
	}

	err = c.updateCertificate(certificateInDap, c.templates.revokeCertificate)

	return err
}

// GetRevokedCerts ...
func (c StorageBackend) GetRevokedCerts() ([]types.RevokedCertificate, error) {
	filter := &conjurapi.ResourceFilter{
		Kind:   "variable",
		Search: "csasarevokedcsasa",
	}
	revokedCerts := []types.RevokedCertificate{}
	resources, err := c.client.Resources(filter)
	if err != nil {
		err = fmt.Errorf("Failed to list resources when attempting to get revoked certificates. %s", err)
		return revokedCerts, err
	}

	for _, resource := range resources {
		revokedCert, err := ParseRevokedCertificate(resource)
		if err != nil {
			return revokedCerts, err
		}
		revokedCerts = append(revokedCerts, revokedCert)
	}

	return revokedCerts, nil
}

// CertificateRevoked Return the types.RevokedCertifcate repersented by the certificate
// If the certificate is not revoked, and empty types.RevokedCertificate is returned
func (c StorageBackend) CertificateRevoked(serialNumber *big.Int) (types.RevokedCertificate, error) {
	variableID := c.getCertificateVariableID(serialNumber.String())

	// Retrieve the specific resource, if not found return error
	resourceID := GetFullResourceID(c.client.GetConfig().Account, "variable", variableID)
	resource, err := c.client.Resource(resourceID)
	if err != nil {
		return types.RevokedCertificate{}, fmt.Errorf("Failed to retrieve certificate with ID '%s'. %s", variableID, err)
	}

	return ParseRevokedCertificate(resource)
}
