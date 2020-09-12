package conjur

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// CreateSSHTemplate Creates a new SSH template in the Conjur backend
func (c StorageBackend) CreateSSHTemplate(template types.SSHTemplate) error {
	variableID := c.getSSHTemplateVariableID(template.TemplateName)

	// validate template does not exists
	_, err := c.client.RetrieveSecret(variableID)
	if err == nil {
		return fmt.Errorf("SSH Template '%s' already exists", template.TemplateName)
	}

	// Template name cannot contain a '/'
	if strings.Contains(template.TemplateName, "/") {
		return fmt.Errorf("SSH Template name '%s' is invalid because it contains a '/'", template.TemplateName)
	}

	// replace template placeholders
	newTemplatePolicy := bytes.NewReader([]byte(
		ReplaceSSHTemplate(template, c.templates.newSSHTemplate)))

	// cast the template stuct into json
	templateJSON, err := json.Marshal(template)
	if err != nil {
		return err
	}

	// Load policy to create the variable
	response, err := c.client.LoadPolicy(
		conjurapi.PolicyModePatch,
		c.getTemplatePolicyBranch(),
		newTemplatePolicy,
	)
	if err != nil {
		return fmt.Errorf("Failed to create SSH Template when loading policy. Message '%v'. %s", response, err)
	}

	// Set the Secret value
	err = c.client.AddSecret(variableID, string(templateJSON))
	return err
}

// ListSSHTemplates Retrieves a list of all templates in the Conjur backend
func (c StorageBackend) ListSSHTemplates() ([]string, error) {
	filter := &conjurapi.ResourceFilter{
		Kind:   "variable",
		Search: "ssh-templates",
	}
	var templateNames []string

	// List resources to get templates
	resources, err := ListResources(c.client, filter)
	if err != nil {
		return templateNames, err
	}

	// Parse the template name for all of the template variables
	for _, resource := range resources {
		_, _, id := SplitConjurID(resource)
		parts := strings.Split(id, "/")
		templatesRoot := parts[len(parts)-2]
		if templatesRoot == "ssh-templates" {
			name := parts[len(parts)-1]
			templateNames = append(templateNames, name)
		}
	}

	return templateNames, nil
}

// GetSSHTemplate Retrieves the information about a given template with `templateName` from
// the Conjur backend
func (c StorageBackend) GetSSHTemplate(templateName string) (types.SSHTemplate, error) {
	variableID := c.getSSHTemplateVariableID(templateName)
	templateJSON, err := c.client.RetrieveSecret(variableID)
	template := &types.SSHTemplate{}

	if err != nil {
		return *template, fmt.Errorf("Failed to retrieve SSH Template with id '%s'. %s", variableID, err)
	}

	err = json.Unmarshal(templateJSON, template)
	if err != nil {
		return *template, fmt.Errorf("Failed to cast '%s' into types.Template. %s", string(templateJSON), err)
	}

	return *template, err
}

// DeleteSSHTemplate Deletes the template with given as `templateName` from the Conjur backend
func (c StorageBackend) DeleteSSHTemplate(templateName string) error {
	// validate template resource exists
	variableID := c.getSSHTemplateVariableID(templateName)
	_, err := c.client.RetrieveSecret(variableID)
	if err != nil {
		return fmt.Errorf("Failed to retrieve SSH Template with id '%s'. %s", variableID, err)
	}

	// remove the template resource
	template := types.SSHTemplate{
		TemplateName: templateName,
	}
	deleteTemplatePolicy := bytes.NewReader([]byte(
		ReplaceSSHTemplate(template, c.templates.deleteSSHTemplate)))
	response, err := c.client.LoadPolicy(
		conjurapi.PolicyModePatch,
		c.getTemplatePolicyBranch(),
		deleteTemplatePolicy,
	)
	if err != nil {
		return fmt.Errorf("Failed to delete SSH Template with id '%s'. Message: '%v'. %s", variableID, response, err)
	}

	return err
}
