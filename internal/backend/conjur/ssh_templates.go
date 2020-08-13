package conjur

import "github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"

func (c StorageBackend) CreateSSHTemplate(template types.SSHTemplate) error {
	return nil
}

func (c StorageBackend) ListSSHTemplates() ([]string, error) {
	return []string{}, nil
}

func (c StorageBackend) GetSSHTemplate(templateName string) (types.SSHTemplate, error) {
	return types.SSHTemplate{}, nil
}

func (c StorageBackend) DeleteSSHTemplate(templateName string) error {
	return nil
}
