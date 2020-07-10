package conjur_test

import (
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend/conjur"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
)

func assertNoError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("Error was returned and was not expected. %s", err)
	}
}

func assertError(t *testing.T, err error) {
	if err == nil {
		t.Errorf("Error was not returned and was expected")
	}
}

func invalidConjurPki() conjur.StorageBackend {
	policyBranch := "not-pki"
	config, _ := conjurapi.LoadConfig()
	client, _ := conjurapi.NewClientFromKey(config,
		authn.LoginPair{
			Login:  "notGood",
			APIKey: "alsoBad",
		})
	templates := conjur.NewDefaultTemplates()
	accessControl := conjur.NewAccessFromDefaults(client.GetConfig(), policyBranch)
	conjurPki := conjur.NewConjurPki(client, policyBranch, templates, accessControl)
	return conjurPki
}

func TestListCertificates(t *testing.T) {
	conjurPKi, err := defaultConjurPki()
	assertNoError(t, err)

	_, err = conjurPKi.ListCertificates()
	assertNoError(t, err)
}

func TestInvalidPolicyBranchListCertificate(t *testing.T) {
	conjurPKi := invalidConjurPki()
	_, err := conjurPKi.ListCertificates()
	assertError(t, err)
}

func TestCertificateRevoked(t *testing.T) {
	conjurPKi, err := defaultConjurPki()
	assertNoError(t, err)

	serialNumber, _ := new(big.Int).SetString("3783992004776553637", 10)
	cert := types.CreateCertificateData{
		Certificate:  "SomeDEREncodedBlob",
		SerialNumber: "3783992004776553637",
	}
	assertNoError(t, err)
	_ = conjurPKi.DeleteCertificate(serialNumber)

	err = conjurPKi.CreateCertificate(cert)
	assertNoError(t, err)

	_, err = conjurPKi.CertificateRevoked(serialNumber)
	assertNoError(t, err)
}

func TestGetRevokedCertificates(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	if err != nil {
		t.Errorf("Failed to init conjurPki interface. %s", err)
	}
	serialNumber, _ := new(big.Int).SetString("88349947748020022222222", 10)
	// Create template for this test case
	cert := types.CreateCertificateData{
		Certificate:  "SomeDEREncodedBlob",
		SerialNumber: "88349947748020022222222",
	}

	_ = conjurPki.DeleteCertificate(serialNumber)

	err = conjurPki.CreateCertificate(cert)
	if err != nil {
		t.Errorf("Failed to create certificate even though it should not exist. %s", err)
	}

	err = conjurPki.RevokeCertificate(serialNumber, 1, time.Now())
	if err != nil {
		t.Errorf("Failed to revoked certficiate even though it should be revokable. %s", err)
	}

	revokedCerts, err := conjurPki.GetRevokedCerts()
	if err != nil {
		t.Errorf("Failed to get revoked certificates. %s", err)
	}

	for _, revokedCert := range revokedCerts {
		if revokedCert.SerialNumber == cert.SerialNumber {
			return
		}
	}

	t.Errorf("Revoked certificate is not '%s'", cert.SerialNumber)
}

func TestRevokeCertificateDoesNotExist(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	if err != nil {
		t.Errorf("Failed to init conjurPki interface. %s", err)
	}
	serialNumber, _ := new(big.Int).SetString("88349947748020022101010", 10)

	err = conjurPki.RevokeCertificate(serialNumber, 1, time.Now())
	if err != nil {
		if !strings.Contains(fmt.Sprintf("%s", err), "404 Not Found") {
			t.Errorf("Invalid error message, certificate should not be found. %s", err)
		}
	}
}

func TestRevokeCertificate(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	if err != nil {
		t.Errorf("Failed to init conjurPki interface. %s", err)
	}
	serialNumber, _ := new(big.Int).SetString("88349947748020022", 10)
	// Create template for this test case
	cert := types.CreateCertificateData{
		Certificate:    "SomeDEREncodedBlob",
		SerialNumber:   "88349947748020022",
		InternalState:  "active",
		ExpirationDate: "7748020022",
	}

	_ = conjurPki.DeleteCertificate(serialNumber)

	err = conjurPki.CreateCertificate(cert)
	if err != nil {
		t.Errorf("Failed to create certificate even though it should not exist. %s", err)
	}

	err = conjurPki.RevokeCertificate(serialNumber, 1, time.Now())
	if err != nil {
		t.Errorf("Failed to revoked certficiate even though it should be revokable. %s", err)
	}
}

func TestCreateCertificate(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	if err != nil {
		t.Errorf("Failed to init conjurPki interface. %s", err)
	}
	serialNumber, _ := new(big.Int).SetString("9389830020029383", 10)
	// Create template for this test case
	cert := types.CreateCertificateData{
		Certificate:  "SomeDEREncodedBlob",
		SerialNumber: "9389830020029383",
	}

	// Load the new template from above
	conjurPki.DeleteCertificate(serialNumber)
	err = conjurPki.CreateCertificate(cert)
	if err != nil {
		t.Errorf("%s", err)
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
	cert := types.CreateCertificateData{
		Certificate:  "SomeDEREncodedBlob",
		SerialNumber: serialNumber.String(),
	}

	conjurPki.CreateCertificate(cert)
	err = conjurPki.CreateCertificate(cert)
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
	newCert := types.CreateCertificateData{
		SerialNumber: serialNumber.String(),
		Certificate:  "someCertificateEncodedStuff",
	}

	conjurPki.CreateCertificate(newCert)
	err = conjurPki.DeleteCertificate(serialNumber)
	if err != nil {
		t.Errorf("Failed to delete certificate '%s' but should be deletable. response: %s", serialNumber.String(), err)
	}
}

func TestDeleteNonExistentCertificate(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	if err != nil {
		t.Errorf("Failed to init conjurPki interface. %s", err)
	}

	serialNumber, _ := new(big.Int).SetString("098765098765", 10)
	err = conjurPki.DeleteCertificate(serialNumber)
	if err == nil {
		t.Errorf("Certificate '%s' was deleted but does not exist", serialNumber.String())
	} else {
		if !strings.Contains(fmt.Sprintf("%s", err), "Failed to retrieve certificate with serial number 'pki/certificates/98765098765'") {
			t.Errorf("Invalid error message: %s", err)
		}
	}
}

func TestListExpiredCertificates(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	if err != nil {
		t.Errorf("Failed to init conjurPki interface. %s", err)
	}
	serialNumber, _ := new(big.Int).SetString("93898300200293809", 10)
	expirationTimeYesterday := time.Now().AddDate(0, 0, -1).Unix()
	// Create template for this test case
	cert := types.CreateCertificateData{
		Certificate:    "SomeDEREncodedBlob",
		SerialNumber:   "93898300200293809",
		ExpirationDate: fmt.Sprintf("%v", expirationTimeYesterday),
	}

	// Load the new template from above
	conjurPki.DeleteCertificate(serialNumber)
	err = conjurPki.CreateCertificate(cert)
	if err != nil {
		t.Errorf("%s", err)
	}

	expiredCerts, err := conjurPki.ListExpiredCertificates(0)
	if err != nil {
		t.Errorf("Failed to retrieve expired certs. %s", err)
	}

	if expiredCerts[0].Cmp(serialNumber) != 0 {
		t.Errorf("The returned expired certificate was not valid. %v and was expecting %v", expiredCerts[0], serialNumber)
	}
	conjurPki.DeleteCertificate(serialNumber)
}

func TestNoListExpiredCertificates(t *testing.T) {
	conjurPki, err := defaultConjurPki()
	if err != nil {
		t.Errorf("Failed to init conjurPki interface. %s", err)
	}
	serialNumber, _ := new(big.Int).SetString("938983002002938091", 10)
	expirationTimeYesterday := time.Now().AddDate(0, 0, 1).Unix()
	// Create template for this test case
	cert := types.CreateCertificateData{
		Certificate:    "SomeDEREncodedBlob",
		SerialNumber:   "938983002002938091",
		ExpirationDate: fmt.Sprintf("%v", expirationTimeYesterday),
	}

	// Load the new template from above
	conjurPki.DeleteCertificate(serialNumber)
	err = conjurPki.CreateCertificate(cert)
	if err != nil {
		t.Errorf("%s", err)
	}

	expiredCerts, err := conjurPki.ListExpiredCertificates(0)
	if err != nil {
		t.Errorf("Failed to retrieve expired certs. %s", err)
	}

	if len(expiredCerts) != 0 {
		t.Errorf("Certifcates returned however no certificates should be expired")
	}
	conjurPki.DeleteCertificate(serialNumber)
}
