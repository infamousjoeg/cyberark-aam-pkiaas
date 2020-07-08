package pki_test

import (
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend/dummy"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/httperror"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/pki"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

func dummyBackend() dummy.Dummy {
	return dummy.Dummy{}
}

func assertNoHttpError(t *testing.T, err httperror.HTTPError) {
	empty := httperror.HTTPError{}
	if err != empty {
		t.Errorf("Unexpected error occured. %v", err)
	}
}

func assertHttpError(t *testing.T, err httperror.HTTPError) {
	empty := httperror.HTTPError{}
	if err == empty {
		t.Errorf("No error was returned and was expected. %v", err)
	}
}

func intermediateRequest() types.IntermediateRequest {
	return types.IntermediateRequest{
		CommonName: "testing.local",
		KeyAlgo:    "RSA",
		KeyBits:    "2048",
	}
}

func TestGenerateIntermediateCSR(t *testing.T) {
	request := intermediateRequest()
	_, err := pki.GenerateIntermediate(request, false, dummyBackend())
	assertNoHttpError(t, err)
}

func TestGenerateIntermediateCSRSelfSigned(t *testing.T) {
	request := intermediateRequest()
	_, err := pki.GenerateIntermediate(request, true, dummyBackend())
	assertNoHttpError(t, err)
}

func TestInvalidSetIntermediateCertificate(t *testing.T) {
	backend := dummyBackend()
	pem := types.PEMCertificate{
		Certificate: "invalidFormat",
	}

	err := pki.SetIntermediateCertificate(pem, backend)
	assertHttpError(t, err)
}

func TestSetIntermediateCertificate(t *testing.T) {
	backend := dummyBackend()
	encodedCert, _ := backend.GetSigningCert()
	derCert, _ := base64.StdEncoding.DecodeString(encodedCert)
	pem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
	pemObj := types.PEMCertificate{
		Certificate: string(pem),
	}

	err := pki.SetIntermediateCertificate(pemObj, backend)
	assertNoHttpError(t, err)
}

func TestGetCA(t *testing.T) {
	backend := dummyBackend()

	_, err := pki.GetCA(backend)
	assertNoHttpError(t, err)
}

func TestGetCAChain(t *testing.T) {
	backend := dummyBackend()

	_, err := pki.GetCAChain(backend)
	assertNoHttpError(t, err)
}

func TestGetCRL(t *testing.T) {
	backend := dummyBackend()

	_, err := pki.GetCRL(backend)
	assertNoHttpError(t, err)
}

// skipped SetCAChain & SetIntermediateCertificate
