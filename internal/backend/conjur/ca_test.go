package conjur_test

import (
	"testing"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend/conjur"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend/dummy"
)

func assertStringsEqual(t *testing.T, expected string, actual string) {
	if expected != actual {
		t.Errorf("The returned string '%s' is not expected '%s'", expected, actual)
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
	policyBranch := "not-pki"
	client, _ := conjur.NewDefaultConjurClient()
	templates := conjur.NewDefaultTemplates()
	accessControl := conjur.NewAccessFromDefaults(client.GetConfig(), policyBranch)
	conjurPki := conjur.NewConjurPki(client, policyBranch, templates, accessControl)

	// Retrieve this chain
	_, err := conjurPki.GetCAChain()
	if err == nil {
		t.Errorf("Retrieved the CA chain even though it does not exists!")
	}
}

func TestWriteSigningCert(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	assertNoError(t, err)

	signingCert, _ := dummy.Dummy{}.GetSigningCert()
	err = conjurPki.WriteSigningCert(signingCert)
	assertNoError(t, err)
}

func TestInvalidWriteSigningCert(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	assertNoError(t, err)

	signingCert := ""
	err = conjurPki.WriteSigningCert(signingCert)
	assertError(t, err)
}

func TestGetSigningCert(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	assertNoError(t, err)

	expectedSigningCert, _ := dummy.Dummy{}.GetSigningCert()
	err = conjurPki.WriteSigningCert(expectedSigningCert)
	assertNoError(t, err)

	returnedSigningCert, err := conjurPki.GetSigningCert()
	assertNoError(t, err)
	assertStringsEqual(t, expectedSigningCert, returnedSigningCert)
}

func TestWriteSigningKey(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	assertNoError(t, err)

	signingKey, _ := dummy.Dummy{}.GetSigningKey()
	err = conjurPki.WriteSigningKey(signingKey)
	assertNoError(t, err)
}

func TestInvalidWriteSigningKey(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	assertNoError(t, err)

	signingKey := ""
	err = conjurPki.WriteSigningKey(signingKey)
	assertError(t, err)
}

func TestGetSigningKey(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	assertNoError(t, err)

	expected, _ := dummy.Dummy{}.GetSigningKey()
	err = conjurPki.WriteSigningKey(expected)
	assertNoError(t, err)

	actual, err := conjurPki.GetSigningKey()
	assertNoError(t, err)
	assertStringsEqual(t, expected, actual)
}

func TestWriteCRL(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	assertNoError(t, err)

	crl, _ := dummy.Dummy{}.GetCRL()
	err = conjurPki.WriteCRL(crl)
	assertNoError(t, err)
}

func TestInvalidWriteCRL(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	assertNoError(t, err)

	crl := ""
	err = conjurPki.WriteCRL(crl)
	assertError(t, err)
}

func TestGetCRL(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	assertNoError(t, err)

	expected, _ := dummy.Dummy{}.GetCRL()
	err = conjurPki.WriteCRL(expected)
	assertNoError(t, err)

	actual, err := conjurPki.GetCRL()
	assertNoError(t, err)
	assertStringsEqual(t, expected, actual)
}
