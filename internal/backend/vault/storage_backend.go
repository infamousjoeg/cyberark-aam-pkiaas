package vault

import (
	"fmt"

	"github.com/hashicorp/vault/api"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/pkg/log"
)

// StorageBackend ...
type StorageBackend struct {
	client *api.Client
	Access AccessControl
}

// GetAccessControl -----
func (c StorageBackend) GetAccessControl() backend.Access {
	return backend.Access(c.Access)
}

// InitConfig ...
// TODO: Might have to initilize some roles?? Not sure right now
func (c StorageBackend) InitConfig() error {
	return nil
}

func defaultVaultClient() (*api.Client, error) {
	config := api.DefaultConfig()
	if config == nil {
		return nil, fmt.Errorf("Failed to get the default config for Vault")
	}
	client, err := api.NewClient(config)
	return client, err
}

// NewDefaultVaultClient return the default conjur client
func NewDefaultVaultClient() (*api.Client, error) {
	return defaultVaultClient()
}

// NewFromDefaults ...
func NewFromDefaults() (StorageBackend, error) {
	client, err := defaultVaultClient()
	if err != nil {
		return StorageBackend{}, fmt.Errorf("Failed to init Vault client: %s", err)
	}
	log.Info("Vault URL: %s", client.Address())

	// Using dummy access control to get the storage backend working correctly first
	return NewVaultPKI(client, NewAccessFromDefaults()), nil
}

// NewVaultPKI ...
func NewVaultPKI(client *api.Client, access AccessControl) StorageBackend {
	return StorageBackend{
		client: client,
		Access: access,
	}
}
