package vault

import (
	"errors"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// CreateSSHTemplate Creates a new SSH template in the Conjur backend
func (c StorageBackend) CreateSSHTemplate(template types.SSHTemplate) error {
	return errors.New("Not implemented")
}

// ListSSHTemplates Retrieves a list of all templates in the Conjur backend
func (c StorageBackend) ListSSHTemplates() ([]string, error) {
	return []string{}, errors.New("Not implemented")

}

// GetSSHTemplate Retrieves the information about a given template with `templateName` from
// the Conjur backend
func (c StorageBackend) GetSSHTemplate(templateName string) (types.SSHTemplate, error) {
	template := &types.SSHTemplate{}
	return *template, errors.New("Not implemented")
}

// DeleteSSHTemplate Deletes the template with given as `templateName` from the Conjur backend
func (c StorageBackend) DeleteSSHTemplate(templateName string) error {
	return errors.New("Not implemented")
}
