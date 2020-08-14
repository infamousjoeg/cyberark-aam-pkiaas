package vault_test

import (
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend/vault"
)

func defaultVaultClient(t *testing.T) *api.Client {
	config := api.DefaultConfig()
	if config == nil {
		t.Errorf("Could get Default config")
	}
	client, err := api.NewClient(config)
	if err != nil {
		t.Errorf("Failed to create new vault client. %s", err)
	}

	return client
}

func TestReadSecretAndGetContent(t *testing.T) {
	client := defaultVaultClient(t)
	_, err := vault.ReadSecretAndGetContent(client, "pki-service/data/test", false)
	if err != nil {
		t.Errorf("Failed to read secet. %s", err)
	}
}

func TestWriteSecretContent(t *testing.T) {
	client := defaultVaultClient(t)
	err := vault.WriteSecretContent(client, "pki-service/data/new", false, "awesomegotitchanging")
	if err != nil {
		t.Errorf("Failed to write secret. %s", err)
	}
}
