package conjur

import (
	"encoding/json"
	"fmt"
)

// GetCAChain ...
func (c StorageBackend) GetCAChain() ([]string, error) {
	variableID := c.getCAChainVariableID()
	caChain := &[]string{}

	value, err := c.client.RetrieveSecret(variableID)
	if err != nil {
		return *caChain, fmt.Errorf("Failed to retrieve certificate chain with variable id '%s'. %s", variableID, err)
	}

	err = json.Unmarshal(value, caChain)
	if err != nil {
		return *caChain, fmt.Errorf("Failed to unmarshal certificate chain. %s", err)
	}

	return *caChain, nil
}

// WriteCAChain ...
func (c StorageBackend) WriteCAChain(certBundle []string) error {
	variableID := c.getCAChainVariableID()

	certBundleJSON, err := json.Marshal(certBundle)
	if err != nil {
		return fmt.Errorf("Failed to marshal cert bundle. %s", err)
	}

	err = c.client.AddSecret(variableID, string(certBundleJSON))
	if err != nil {
		return fmt.Errorf("Failed to set certificate chain with variable id '%s'. %s", variableID, err)
	}

	return nil
}

// GetSigningCert ...
func (c StorageBackend) GetSigningCert() (string, error) {
	variableID := c.getSigningCertVariableID()

	value, err := c.client.RetrieveSecret(variableID)
	if err != nil {
		return "", fmt.Errorf("Failed to retrieve signing certificate with variable id '%s'. %s", variableID, err)
	}

	return string(value), nil
}

// WriteSigningCert ...
func (c StorageBackend) WriteSigningCert(content string) error {
	variableID := c.getSigningCertVariableID()

	err := c.client.AddSecret(variableID, content)
	if err != nil {
		return fmt.Errorf("Failed to set signing certificate with variable id '%s'. %s", variableID, err)
	}

	return nil
}

// GetSigningKey ...
func (c StorageBackend) GetSigningKey() (string, error) {
	variableID := c.getSigningKeyVariableID()

	value, err := c.client.RetrieveSecret(variableID)
	if err != nil {
		return "", fmt.Errorf("Failed to retrieve signing key with variable id '%s'. %s", variableID, err)
	}

	return string(value), nil
}

// WriteSigningKey ...
func (c StorageBackend) WriteSigningKey(content string) error {
	variableID := c.getSigningKeyVariableID()

	err := c.client.AddSecret(variableID, content)
	if err != nil {
		return fmt.Errorf("Failed to set signing key with variable id '%s'. %s", variableID, err)
	}

	return nil
}

// GetCRL ...
func (c StorageBackend) GetCRL() (string, error) {
	variableID := c.getCRLVariableID()

	value, err := c.client.RetrieveSecret(variableID)
	if err != nil {
		return "", fmt.Errorf("Failed to retrieve CRL with variable id '%s'. %s", variableID, err)
	}

	return string(value), nil
}

// WriteCRL ...
func (c StorageBackend) WriteCRL(content string) error {
	variableID := c.getCRLVariableID()

	err := c.client.AddSecret(variableID, content)
	if err != nil {
		return fmt.Errorf("Failed to set CRL with variable id '%s'. %s", variableID, err)
	}

	return nil
}
