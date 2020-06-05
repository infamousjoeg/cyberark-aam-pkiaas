package conjur_test

import (
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/conjur"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

func testCreateTemplate() string {
	return `- !variable
  id: <TemplateName>
`
}

func testCreateCertificate() string {
	return `- !variable
  id: "<SerialNumber>"
`
}

func testDeleteTemplate() string {
	return `- !delete
  record: !variable <TemplateName>
`
}

func testDeleteCertificate() string {
	return `- !delete
  record: !variable <SerialNumber>
`
}

func expectedPolicy() string {
	return `- !variable
  id: TestTemplate
`
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func defaultConjurClient() (*conjurapi.Client, error) {
	config, err := conjurapi.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("Failed to init config from environment variables. %s", err)
	}
	client, err := conjurapi.NewClientFromEnvironment(config)
	if err != nil {
		return nil, fmt.Errorf("Failed to init client from config. %s", err)
	}
	return client, err
}

func defaultTemplates() conjur.ConjurTemplates {
	return conjur.NewTemplates(testCreateTemplate(), testDeleteTemplate(), testCreateCertificate(), testDeleteCertificate())
}

func defaultConjurPki() (conjur.ConjurPki, error) {
	client, err := defaultConjurClient()
	if err != nil {
		return conjur.ConjurPki{}, err
	}
	templates := defaultTemplates()
	return conjur.NewConjurPki(client, "pki", templates), err
}

func defaultTemplate() types.Template {
	return types.Template{
		TemplateName: "template_name",
		KeyAlgo:      "something",
	}
}

func TestReplaceTemplate(t *testing.T) {
	testTemplate := testCreateTemplate()
	newTemplate := types.Template{
		TemplateName: "TestTemplate",
	}
	result := conjur.ReplaceTemplate(newTemplate, testTemplate)
	if result != expectedPolicy() {
		t.Errorf("Template result '%q' does not meet expected value '%q'", result, expectedPolicy())
	}
}

func TestCreateTemplate(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	if err != nil {
		t.Errorf("Failed to init conjurPki interface. %s", err)
	}

	// Create template for this test case
	template := types.Template{
		TemplateName: "test_create_template",
		KeyAlgo:      "someAlgo",
	}
	conjurPki.DeleteTemplate(template.TemplateName)

	// Load the new template from above
	response, err := conjurPki.CreateTemplate(template)
	if err != nil {
		t.Errorf("%v, %s", response, err)
	}

	// retrieve the stored template
	storedTemplate, err := conjurPki.GetTemplate(template.TemplateName)
	if err != nil {
		t.Errorf("Failed to retrieve stored template. %s", err)
	}

	// validate that they are equal
	if !reflect.DeepEqual(template, storedTemplate) {
		t.Errorf("Templates are not equal!! '%v' is not equal to '%v'", template, storedTemplate)
	}
}

func TestCreateTemplateAlreadyExists(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	if err != nil {
		t.Errorf("Failed to init conjurPki interface. %s", err)
	}

	// Create template for this test case
	template := types.Template{
		TemplateName: "test_create_template_already_exists",
		KeyAlgo:      "someAlgo",
	}
	conjurPki.DeleteTemplate(template.TemplateName)

	// Load the new template from above
	response, err := conjurPki.CreateTemplate(template)
	if err != nil {
		t.Errorf("%v, %s", response, err)
	}

	// Load the new template again and it should fail
	response, err = conjurPki.CreateTemplate(template)
	if err == nil {
		t.Errorf("Loading a template twice in a row should result in an error, template already exists.")
	}
}

func TestDeleteTemplate(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	if err != nil {
		t.Errorf("Failed to init conjurPki interface. %s", err)
	}

	// Create template for this test case
	template := types.Template{
		TemplateName: "test_delete_template",
		KeyAlgo:      "someAlgo",
	}

	// Load the new template from above
	response, err := conjurPki.CreateTemplate(template)
	if err != nil {
		t.Errorf("%v, %s", response, err)
	}
	// something
	// Delete the template, should be successful
	response, err = conjurPki.DeleteTemplate(template.TemplateName)
	if err != nil {
		t.Errorf("Error: %v, %s", response, err)
	}
}

func TestDeleteNonExistentTemplate(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	if err != nil {
		t.Errorf("Failed to init conjurPki interface. %s", err)
	}

	_, err = conjurPki.DeleteTemplate("notRealTemplate")
	if err == nil {
		t.Errorf("Delete template that does not exist should fail.")
	}

	if err != nil {
		if !strings.Contains(fmt.Sprintf("%s", err), "Failed to retrieve template with id 'pki/templates/notRealTemplate'. 404 Not Found. Variable 'pki/templates/notRealTemplate' not found in account 'conjur'") {
			t.Errorf("Invalid error message returned. %s", err)
		}
	}
}

func TestListTemplates(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	if err != nil {
		t.Errorf("Failed to init conjurPki interface. %s", err)
	}

	// Create template for this test case
	template1 := types.Template{
		TemplateName: "test_list_template_1",
		KeyAlgo:      "someAlgo",
	}

	template2 := types.Template{
		TemplateName: "test_list_template_2",
		KeyAlgo:      "someAlgo",
	}

	template3 := types.Template{
		TemplateName: "test_list_template_3",
		KeyAlgo:      "someAlgo",
	}

	// Load the new template from above
	conjurPki.CreateTemplate(template1)
	conjurPki.CreateTemplate(template2)
	conjurPki.CreateTemplate(template3)

	templates, err := conjurPki.ListTemplates()
	if err != nil {
		t.Errorf("Failed to list templates. %s", err)
	}
	if !stringInSlice("test_list_template_1", templates) {
		t.Errorf("Failed to find template 'test_list_template_1', %v", templates)
	}

	if !stringInSlice("test_list_template_2", templates) {
		t.Errorf("Failed to find template 'test_list_template_2', %v", templates)

	}

	if !stringInSlice("test_list_template_3", templates) {
		t.Errorf("Failed to find template 'test_list_template_3', %v", templates)

	}
}

func TestGetTemplate(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	if err != nil {
		t.Errorf("Failed to init conjurPki interface. %s", err)
	}

	// Create template for this test case
	template := types.Template{
		TemplateName: "test_get_template",
		KeyAlgo:      "someAlgo",
	}
	conjurPki.DeleteTemplate(template.TemplateName)
	conjurPki.CreateTemplate(template)
	storedTemplate, err := conjurPki.GetTemplate(template.TemplateName)
	if err != nil {
		t.Errorf("Failed to retrieve the stored template. %s", err)
	}

	// validate that they are equal
	if !reflect.DeepEqual(template, storedTemplate) {
		t.Errorf("Templates are not equal!! '%v' is not equal to '%v'", template, storedTemplate)
	}
}

func TestGetNonExistentTemplate(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	if err != nil {
		t.Errorf("Failed to init conjurPki interface. %s", err)
	}

	// Create template for this test case
	template := types.Template{
		TemplateName: "test_get_non_existent_template",
		KeyAlgo:      "someAlgo",
	}

	storedTemplate, err := conjurPki.GetTemplate(template.TemplateName)
	if err == nil {
		t.Errorf("Retrieved a template that should not exists %v", storedTemplate)
	} else {
		if !strings.Contains(fmt.Sprintf("%s", err), "Failed to retrieve template with id 'pki/templates/test_get_non_existent_template'. 404 Not Found. Variable 'pki/templates/test_get_non_existent_template' not found in account 'conjur'") {
			t.Errorf("Invalid error message. %s", err)
		}
	}
}

func TestCreateCertificate(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	if err != nil {
		t.Errorf("Failed to init conjurPki interface. %s", err)
	}
	serialNumber, _ := new(big.Int).SetString("9389830020029383", 10)
	// Create template for this test case
	cert := types.CreateCertificateInDap{
		Certificate:  "SomeDEREncodedBlob",
		SerialNumber: "9389830020029383",
	}

	// Load the new template from above
	conjurPki.DeleteCertificate(serialNumber)
	response, err := conjurPki.CreateCertificate(cert)
	if err != nil {
		t.Errorf("%v, %s", response, err)
	}

	// retrieve the stored template
	storedCertificate, err := conjurPki.GetCertificate(serialNumber)
	if err != nil {
		t.Errorf("Failed to retrieve stored template. %s", err)
	}

	// validate that they are equal
	if !reflect.DeepEqual(cert.Certificate, storedCertificate) {
		t.Errorf("Templates are not equal!! '%v' is not equal to '%v'", cert.Certificate, storedCertificate)
	}
}

func TestCreateCertificateAlreadyExists(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	if err != nil {
		t.Errorf("Failed to init conjurPki interface. %s", err)
	}
	serialNumber, _ := new(big.Int).SetString("12345543211234", 10)
	// Create template for this test case
	cert := types.CreateCertificateInDap{
		Certificate:  "SomeDEREncodedBlob",
		SerialNumber: serialNumber.String(),
	}

	conjurPki.CreateCertificate(cert)
	_, err = conjurPki.CreateCertificate(cert)
	if err == nil {
		t.Errorf("Created a certificate even though '%s' is already created", serialNumber.String())
	}

}

func TestDeleteCertificate(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	if err != nil {
		t.Errorf("Failed to init conjurPki interface. %s", err)
	}

	serialNumber, _ := new(big.Int).SetString("838837738982929383", 10)
	newCert := types.CreateCertificateInDap{
		SerialNumber: serialNumber.String(),
	}

	conjurPki.CreateCertificate(newCert)
	response, err := conjurPki.DeleteCertificate(serialNumber)
	if err != nil {
		t.Errorf("Failed to delete certificate '%s' but should be deletable. response: %v", serialNumber.String(), response)
	}
}

func TestDeleteNonExistentCertificate(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	if err != nil {
		t.Errorf("Failed to init conjurPki interface. %s", err)
	}

	serialNumber, _ := new(big.Int).SetString("098765098765", 10)
	_, err = conjurPki.DeleteCertificate(serialNumber)
	if err == nil {
		t.Errorf("Certificate '%s' was deleted but does not exist", serialNumber.String())
	} else {
		if !strings.Contains(fmt.Sprintf("%s", err), "Failed to retrieve certificate with serial number 'pki/certificates/98765098765'") {
			t.Errorf("Invalid error message: %s", err)
		}
	}
}

func TestWriteCAChain(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	if err != nil {
		t.Errorf("Failed to init conjurPki interface. %s", err)
	}

	// write chain "hello", "world"
	chain := []string{"hello", "world"}
	err = conjurPki.WriteCAChain(chain)
	if err != nil {
		t.Errorf("Failed to write to CA Chain. %s", err)
	}

	// Retrieve this chain
	storedChain, err := conjurPki.GetCAChain()
	if err != nil {
		t.Errorf("Failed to retrieve ca chain even though it exists!")
	}

	// Validate order of the chain and contents are the same
	for i, pem := range chain {
		storedPEM := storedChain[i]
		if pem != storedPEM {
			t.Errorf("PEM created does not match PEM Stored. '%s' does not equal '%s'", pem, storedPEM)
		}
	}
}

func TestGetCAChainNonExistent(t *testing.T) {
	client, _ := defaultConjurClient()
	templates := defaultTemplates()
	conjurPki := conjur.NewConjurPki(client, "not-pki", templates)

	// Retrieve this chain
	_, err := conjurPki.GetCAChain()
	if err == nil {
		t.Errorf("Retrieve the CA chain even though it does not exists!")
	}
}
