package vault

import (
	"encoding/json"
	"fmt"
)

func getCAChainPath() string {
	return rootPath() + "/ca/chain"
}

func getSigningCertPath() string {
	return rootPath() + "/ca/cert"
}

func getSigningKeyPath() string {
	return rootPath() + "/ca/key"
}

func getCRLPath() string {
	return rootPath() + "/crl"
}

// GetCAChain ...
func (c StorageBackend) GetCAChain() ([]string, error) {
	secretPath := getCAChainPath()
	caChain := &[]string{}

	value, err := readSecretAndGetContent(c.client, secretPath, true)
	if err != nil {
		return *caChain, err
	}

	err = json.Unmarshal([]byte(value), caChain)
	if err != nil {
		return *caChain, fmt.Errorf("Failed to unmarshal certificate chain. %s", err)
	}

	return *caChain, nil
}

// WriteCAChain ...
func (c StorageBackend) WriteCAChain(certBundle []string) error {
	secretPath := getCAChainPath()

	certBundleJSON, err := json.Marshal(certBundle)
	if err != nil {
		return fmt.Errorf("Failed to marshal cert bundle. %s", err)
	}

	return writeSecretContent(c.client, secretPath, true, string(certBundleJSON))
}

// GetSigningCert ...
func (c StorageBackend) GetSigningCert() (string, error) {
	secretPath := getSigningCertPath()
	return readSecretAndGetContent(c.client, secretPath, true)
}

// WriteSigningCert ...
func (c StorageBackend) WriteSigningCert(content string) error {
	secretPath := getSigningCertPath()
	return writeSecretContent(c.client, secretPath, true, content)
}

// GetSigningKey ...
func (c StorageBackend) GetSigningKey() (string, error) {
	secretPath := getSigningKeyPath()
	return readSecretAndGetContent(c.client, secretPath, true)
}

// WriteSigningKey ...
func (c StorageBackend) WriteSigningKey(content string) error {
	secretPath := getSigningKeyPath()
	return writeSecretContent(c.client, secretPath, true, content)
}

// GetCRL ...
func (c StorageBackend) GetCRL() (string, error) {
	secretPath := getCRLPath()
	return readSecretAndGetContent(c.client, secretPath, true)
}

// WriteCRL ...
func (c StorageBackend) WriteCRL(content string) error {
	secretPath := getCRLPath()
	return writeSecretContent(c.client, secretPath, true, content)
}
