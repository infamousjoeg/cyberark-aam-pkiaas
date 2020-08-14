package vault

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

func getTemplatesSecretPath() string {
	return rootPath() + "/templates/"
}

func getTemplateSecretPath(templateName string) string {
	return rootPath() + "/templates/" + templateName
}

// CreateTemplate ...
func (c StorageBackend) CreateTemplate(template types.Template) error {
	secretPath := getTemplateSecretPath(template.TemplateName)
	_, err := readSecretAndGetContent(c.client, secretPath, false)
	if err == nil {
		return fmt.Errorf("Template '%s' already exists", template.TemplateName)
	}
	// Template name cannot contain a '/'
	if strings.Contains(template.TemplateName, "/") {
		return fmt.Errorf("Template name '%s' is invalid because it contains a '/'", template.TemplateName)
	}

	// cast the template stuct into json
	templateJSON, err := json.Marshal(template)
	if err != nil {
		return err
	}

	return writeSecretContent(c.client, secretPath, true, string(templateJSON))
}

// ListTemplates ...
func (c StorageBackend) ListTemplates() ([]string, error) {
	secretPath := getTemplatesSecretPath()
	return listKVs(c.client, secretPath)
}

// GetTemplate ...
func (c StorageBackend) GetTemplate(templateName string) (types.Template, error) {
	secretPath := getTemplateSecretPath(templateName)
	template := &types.Template{
		StoreCertificate: true,
	}

	value, err := readSecretAndGetContent(c.client, secretPath, true)
	if err != nil {
		return *template, err
	}

	err = json.Unmarshal([]byte(value), template)
	if err != nil {
		return *template, fmt.Errorf("Failed to cast '%s' into types.Template. %s", value, err)
	}

	return *template, err
}

// DeleteTemplate ...
func (c StorageBackend) DeleteTemplate(templateName string) error {
	secretPath := getTemplateSecretPath(templateName)
	_, err := c.client.Logical().Delete(secretPath)
	return err
}
