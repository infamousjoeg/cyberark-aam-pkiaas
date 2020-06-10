package conjur

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// ReplaceTemplate ...
// TODO: If a variable value is empty should we not create it or should we leave it empty on the conjur side?
func ReplaceTemplate(template types.Template, templateContent string) string {
	newTemplate := templateContent

	e := reflect.ValueOf(&template).Elem()
	for i := 0; i < e.NumField(); i++ {
		varName := e.Type().Field(i).Name
		varName = "<" + varName + ">"
		varValue := e.Field(i).Interface()

		newTemplate = strings.ReplaceAll(newTemplate, varName, fmt.Sprintf("%v", varValue))
	}

	return newTemplate
}

// ReplaceCertificate ...
func ReplaceCertificate(cert types.CreateCertificateData, certificateContent string) string {
	newCertificate := certificateContent

	e := reflect.ValueOf(&cert).Elem()
	for i := 0; i < e.NumField(); i++ {
		varName := e.Type().Field(i).Name
		varName = "<" + varName + ">"
		varValue := e.Field(i).Interface()
		newCertificate = strings.ReplaceAll(newCertificate, varName, fmt.Sprintf("%v", varValue))
	}

	return newCertificate
}

// ListResources ...
func ListResources(client *conjurapi.Client, filter *conjurapi.ResourceFilter) ([]string, error) {
	resources, err := client.Resources(filter)
	var resourceIds []string

	if err != nil {
		err = fmt.Errorf("Failed to list resources. %s", err)
		return resourceIds, err
	}

	for _, resource := range resources {
		id := resource["id"].(string)
		resourceIds = append(resourceIds, id)
	}

	return resourceIds, nil
}

// SplitConjurID ... returns account, kind, id
func SplitConjurID(fullID string) (string, string, string) {
	parts := strings.SplitN(fullID, ":", 3)
	return parts[0], parts[1], parts[2]
}

// GetAnnotationValue ...
// This method assumes that the key is on the given resource
// If this annotation is not present on the resource an error will be returned
// If the annotation is found but the value is empty than an empty string is returned and no error.
func GetAnnotationValue(resource map[string]interface{}, key string) (string, error) {
	annotations := resource["annotations"].([]interface{})
	value := ""
	keyFound := false

	for _, annotation := range annotations {
		a := annotation.(map[string]interface{})
		keyName := a["name"].(string)
		if keyName == key {
			value = a["value"].(string)
			keyFound = true
			break
		}
	}

	if !keyFound {
		return value, fmt.Errorf("Failed to find annotation '%s' on resource '%v'", key, resource)
	}

	return value, nil
}
