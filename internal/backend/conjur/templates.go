package conjur

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// CreateTemplate ...
func (c StorageBackend) CreateTemplate(template types.Template) error {
	variableID := c.getTemplateVariableID(template.TemplateName)

	// validate template does not exists
	_, err := c.client.RetrieveSecret(variableID)
	if err == nil {
		return fmt.Errorf("Template '%s' already exists", template.TemplateName)
	}

	// Template name cannot contain a '/'
	if strings.Contains(template.TemplateName, "/") {
		return fmt.Errorf("Template name '%s' is invalid because it contains a '/'", template.TemplateName)
	}

	// replace template placeholders
	newTemplatePolicy := bytes.NewReader([]byte(
		ReplaceTemplate(template, c.templates.newTemplate)))

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
		return fmt.Errorf("Failed to create template when loading policy. Message '%v'. %s", response, err)
	}

	// Set the Secret value
	err = c.client.AddSecret(variableID, string(templateJSON))
	return err
}

// ListTemplates ...
func (c StorageBackend) ListTemplates() ([]string, error) {
	filter := &conjurapi.ResourceFilter{
		Kind:   "variable",
		Search: "templates",
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
		if templatesRoot == "templates" {
			name := parts[len(parts)-1]
			templateNames = append(templateNames, name)
		}
	}

	return templateNames, err
}

// GetTemplate ...
func (c StorageBackend) GetTemplate(templateName string) (types.Template, error) {
	variableID := c.getTemplateVariableID(templateName)
	templateJSON, err := c.client.RetrieveSecret(variableID)
	template := &types.Template{}

	if err != nil {
		return *template, fmt.Errorf("Failed to retrieve template with id '%s'. %s", variableID, err)
	}

	err = json.Unmarshal(templateJSON, template)
	if err != nil {
		return *template, fmt.Errorf("Failed to cast '%s' into types.Template. %s", string(templateJSON), err)
	}

	return *template, err
}

// DeleteTemplate ...
func (c StorageBackend) DeleteTemplate(templateName string) error {
	// validate template resource exists
	variableID := c.getTemplateVariableID(templateName)
	_, err := c.client.RetrieveSecret(variableID)
	if err != nil {
		return fmt.Errorf("Failed to retrieve template with id '%s'. %s", variableID, err)
	}

	// remove the template resource
	template := types.Template{
		TemplateName: templateName,
	}
	deleteTemplatePolicy := bytes.NewReader([]byte(
		ReplaceTemplate(template, c.templates.deleteTemplate)))
	response, err := c.client.LoadPolicy(
		conjurapi.PolicyModePatch,
		c.getTemplatePolicyBranch(),
		deleteTemplatePolicy,
	)
	if err != nil {
		return fmt.Errorf("Failed to delete template with id '%s'. Message: '%v'. %s", variableID, response, err)
	}

	return err
}
