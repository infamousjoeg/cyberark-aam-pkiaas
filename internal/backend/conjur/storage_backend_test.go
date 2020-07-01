package conjur_test

import (
	"testing"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend/conjur"
)

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func defaultConjurPki() (conjur.StorageBackend, error) {
	return conjur.NewFromDefaults()
}

func TestInitConfig(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	if err != nil {
		t.Errorf("Failed to init conjurPki interface. %s", err)
	}
	err = conjurPki.InitConfig()
	if err != nil {
		t.Errorf("Failed to init the pki config. %s", err)
	}
}
