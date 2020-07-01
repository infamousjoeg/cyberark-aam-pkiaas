package pki_test

import (
	"math/big"
	"testing"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/httperror"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/pki"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

func assertExpectedHttpError(t *testing.T, expected httperror.HTTPError, actual httperror.HTTPError) {
	if expected.ErrorCode != actual.ErrorCode {
		t.Errorf("Recieved error code '%s' was was expecting '%s'", actual.ErrorCode, expected.ErrorCode)
	}
	if expected.HTTPResponse != actual.HTTPResponse {
		t.Errorf("Recieved status code '%v' was was expecting '%v'", actual.HTTPResponse, expected.HTTPResponse)
	}
}

func createCertRequest() types.CreateCertReq {
	return types.CreateCertReq{
		TemplateName: "TestTemplate",
		CommonName:   "testing.local",
		TTL:          1440,
	}
}

func TestCreateCert(t *testing.T) {
	storage := dummyBackend()
	createCert := createCertRequest()
	_, err := pki.CreateCert(createCert, storage)
	assertNoHttpError(t, err)
}

func TestInvalidTemplateCreateCert(t *testing.T) {
	backend := dummyBackend()
	createCert := createCertRequest()
	createCert.TemplateName = "notRealTenplate"
	_, err := pki.CreateCert(createCert, backend)
	assertHttpError(t, err)
}

func TestGetCert(t *testing.T) {
	backend := dummyBackend()
	serial := big.NewInt(10351605685901192)
	serialNumber, _ := pki.ConvertSerialIntToOctetString(serial)
	_, err := pki.GetCert(serialNumber, backend)
	assertNoHttpError(t, err)
}

func TestInvalidSerialNumberGetCert(t *testing.T) {
	backend := dummyBackend()
	_, err := pki.GetCert("10351605685901192", backend)
	assertHttpError(t, err)
}

func TestListCerts(t *testing.T) {
	backend := dummyBackend()
	_, err := pki.ListCerts(backend)
	assertNoHttpError(t, err)
}

func TestRevokeCert(t *testing.T) {
	backend := dummyBackend()
	serial := big.NewInt(10351605685901192)
	serialNumber, _ := pki.ConvertSerialIntToOctetString(serial)
	request := types.RevokeRequest{
		SerialNumber: serialNumber,
		Reason:       "keyCompromise",
	}

	err := pki.RevokeCert(request, backend)
	assertNoHttpError(t, err)
}

// Skipped SignCert() success
