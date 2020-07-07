package conjur_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend/conjur"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

func testCreateTemplate() string {
	return `- !variable
  id: <TemplateName>
`
}

func expectedPolicy() string {
	return `- !variable
  id: TestTemplate
`
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
	err = conjurPki.CreateTemplate(template)
	if err != nil {
		t.Errorf("%s", err)
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
	err = conjurPki.CreateTemplate(template)
	if err != nil {
		t.Errorf("%s", err)
	}

	// Load the new template again and it should fail
	err = conjurPki.CreateTemplate(template)
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
	err = conjurPki.CreateTemplate(template)
	if err != nil {
		t.Errorf("%s", err)
	}
	// something
	// Delete the template, should be successful
	err = conjurPki.DeleteTemplate(template.TemplateName)
	if err != nil {
		t.Errorf("%s", err)
	}
}

func TestDeleteNonExistentTemplate(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	if err != nil {
		t.Errorf("Failed to init conjurPki interface. %s", err)
	}

	err = conjurPki.DeleteTemplate("notRealTemplate")
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
