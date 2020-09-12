package conjur

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

// StringToTime take an EPOCH string and convert to time.Time
func StringToTime(s string) (time.Time, error) {
	sec, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(sec, 0), nil
}

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

// ReplaceSSHTemplate Replace the ssh template content with TemplateName
func ReplaceSSHTemplate(template types.SSHTemplate, templateContent string) string {
	return strings.ReplaceAll(templateContent, "<TemplateName>", template.TemplateName)
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

// SplitConjurID returns account, kind, id
func SplitConjurID(fullID string) (string, string, string) {
	parts := strings.SplitN(fullID, ":", 3)
	return parts[0], parts[1], parts[2]
}

// GetFullResourceID  returns string of the full resource id
func GetFullResourceID(account string, kind string, id string) string {
	return strings.Join([]string{account, kind, id}, ":")
}

// ParseRevokedCertificate Recieve a resource and return a types.RevokedCertificate object
func ParseRevokedCertificate(resource map[string]interface{}) (types.RevokedCertificate, error) {
	// Split the full ID to get the serialNumber
	fullID := resource["id"].(string)
	_, _, id := SplitConjurID(fullID)
	parts := strings.Split(id, "/")
	serialNumberString := parts[len(parts)-1]

	// Get the Revoked annotation, if this certificare is not revoked return empty RevokedCertificates object
	revoked, err := GetAnnotationValue(resource, "Revoked")
	if err != nil {
		return types.RevokedCertificate{}, fmt.Errorf("Failed to retrieve Revoked from certificate '%s'. %s", serialNumberString, err)
	}
	if strings.ToLower(revoked) != "true" {
		return types.RevokedCertificate{}, nil
	}

	// Get the RevocationReasonCode
	reasonCode, err := GetAnnotationValue(resource, "RevocationReasonCode")
	if err != nil {
		return types.RevokedCertificate{}, fmt.Errorf("Failed to retrieve RevocationReasonCode from certificate '%s'. %s", serialNumberString, err)
	}

	// Get the Revocation Date
	revocationDate, err := GetAnnotationValue(resource, "RevocationDate")
	if err != nil {
		return types.RevokedCertificate{}, fmt.Errorf("Failed to retrieve RevocationDate from certificate '%s'. %s", serialNumberString, err)
	}

	reasonCodeInt, err := strconv.Atoi(reasonCode)
	if err != nil {
		return types.RevokedCertificate{}, fmt.Errorf("Failed to cast RevocationReasonCode '%s' into an int", reasonCode)
	}

	revocationDateInt, err := strconv.Atoi(revocationDate)
	if err != nil {
		return types.RevokedCertificate{}, fmt.Errorf("Failed to cast RevocationDate '%s' into an int", revocationDate)
	}

	dateTime := time.Unix(int64(revocationDateInt), 0)

	revokedCert := types.RevokedCertificate{
		SerialNumber:   serialNumberString,
		ReasonCode:     reasonCodeInt,
		RevocationDate: dateTime,
	}

	return revokedCert, nil
}

// IsCertificateExpired this function will take in a certificate resource, the current time and the day buffer
// It will check if the current time is past the expirationTime with the day buffer added to the expiration time
func IsCertificateExpired(resource map[string]interface{}, currentTime time.Time, dayBuffer int) bool {
	value, err := GetAnnotationValue(resource, "ExpirationDate")
	if err != nil {
		return false
	}

	expirationTime, err := StringToTime(value)
	if err != nil {
		return false
	}

	// Add buffer days to expiration date
	expirationTime = expirationTime.AddDate(0, 0, dayBuffer)

	return currentTime.After(expirationTime)
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
