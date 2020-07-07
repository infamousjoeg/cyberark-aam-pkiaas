package pki_test

import (
	"testing"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/pki"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

func defaultTemplate() types.Template {
	return types.Template{
		TemplateName: "TestTemplate",
		KeyAlgo:      "RSA",
		KeyBits:      "2048",
	}
}

func TestCreateTemplate(t *testing.T) {
	backend := dummyBackend()
	template := defaultTemplate()
	err := pki.CreateTemplate(template, backend)
	assertNoHttpError(t, err)
}

func TestDeleteTemplate(t *testing.T) {
	backend := dummyBackend()
	template := defaultTemplate()
	err := pki.DeleteTemplate(template.TemplateName, backend)
	assertNoHttpError(t, err)
}

func TestGetTemplate(t *testing.T) {
	backend := dummyBackend()
	template := defaultTemplate()
	_, err := pki.GetTemplate(template.TemplateName, backend)
	assertNoHttpError(t, err)
}

func TestListTemplate(t *testing.T) {
	backend := dummyBackend()
	_, err := pki.ListTemplate(backend)
	assertNoHttpError(t, err)
}
