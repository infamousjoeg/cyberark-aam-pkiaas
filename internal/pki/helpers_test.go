package pki_test

import (
	"strings"
	"testing"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/pki"
)

func errorContains(err error, sub string) bool {
	if strings.Contains(err.Error(), sub) {
		return true
	}
	return false
}

func TestValidateContentType(t *testing.T) {
	header := make(map[string][]string)
	header["Content-Type"] = []string{"application/json"}
	valid := pki.ValidateContentType(header, "application/json")
	if !valid {
		t.Errorf("Failed to validate Content-Type of application/json")
	}
}

func TestInvalidContentType(t *testing.T) {
	header := make(map[string][]string)
	header["Content-Type"] = []string{"not/application/json"}
	valid := pki.ValidateContentType(header, "application/json")
	if valid {
		t.Errorf("Validated successfully however Content-Type is invalid")
	}
}

func TestGenerateKeysRsa2048(t *testing.T) {
	algo := "RsA"
	keySize := "2048"
	privateKey, publicKey, err := pki.GenerateKeys(algo, keySize)
	if privateKey == "" {
		t.Errorf("Failed to generate private key for '%s' with key size of '%s'. %s", algo, keySize, err)
	}
	if publicKey == "" {
		t.Errorf("Failed to generate public key for '%s' with key size of '%s'. %s ", algo, keySize, err)
	}
	if err != nil {
		t.Errorf("Failed to generate public & private key for '%s' with key size of '%s'. %s", algo, keySize, err)
	}
}

func TestGenerateKeysRsaKeySizeNonInteger(t *testing.T) {
	algo := "rsa"
	keySize := "notAnInteger"
	_, _, err := pki.GenerateKeys(algo, keySize)
	if err == nil {
		t.Errorf("Generate public & private key successfully even though keySize is invalid.  %s", err)
	}
	if !errorContains(err, "The key size for RSA keys is required to be an integer greater than 2048 bits") {
		t.Errorf("Invalid error returned when using invalid keyAlgo. %s", err)
	}
}

func TestGenerateKeysRsaLowKeyBits(t *testing.T) {
	algo := "rsa"
	keySize := "1024"
	_, _, err := pki.GenerateKeys(algo, keySize)
	if err == nil {
		t.Errorf("Generate public & private key successfully even though keySize is invalid.  %s", err)
	}
	if !errorContains(err, "The minimum supported size for RSA keys is 2048 bits") {
		t.Errorf("Invalid error returned when using invalid keyAlgo. %s", err)
	}
}

func TestGenerateKeysECDSAp224(t *testing.T) {
	algo := "ECDSA"
	keySize := "p224"
	privateKey, publicKey, err := pki.GenerateKeys(algo, keySize)
	if privateKey == "" {
		t.Errorf("Failed to generate private key for '%s' with key size of '%s'. %s", algo, keySize, err)
	}
	if publicKey == "" {
		t.Errorf("Failed to generate public key for '%s' with key size of '%s'. %s ", algo, keySize, err)
	}
	if err != nil {
		t.Errorf("Failed to generate public & private key for '%s' with key size of '%s'. %s", algo, keySize, err)
	}
}

func TestGenerateKeysECDSAp256(t *testing.T) {
	algo := "ECDSA"
	keySize := "p256"
	privateKey, publicKey, err := pki.GenerateKeys(algo, keySize)
	if privateKey == "" {
		t.Errorf("Failed to generate private key for '%s' with key size of '%s'. %s", algo, keySize, err)
	}
	if publicKey == "" {
		t.Errorf("Failed to generate public key for '%s' with key size of '%s'. %s ", algo, keySize, err)
	}
	if err != nil {
		t.Errorf("Failed to generate public & private key for '%s' with key size of '%s'. %s", algo, keySize, err)
	}
}

func TestGenerateKeysECDSAp384(t *testing.T) {
	algo := "ECDSA"
	keySize := "p224"
	privateKey, publicKey, err := pki.GenerateKeys(algo, keySize)
	if privateKey == "" {
		t.Errorf("Failed to generate private key for '%s' with key size of '%s'. %s", algo, keySize, err)
	}
	if publicKey == "" {
		t.Errorf("Failed to generate public key for '%s' with key size of '%s'. %s ", algo, keySize, err)
	}
	if err != nil {
		t.Errorf("Failed to generate public & private key for '%s' with key size of '%s'. %s", algo, keySize, err)
	}
}

func TestGenerateKeysECDSAp521(t *testing.T) {
	algo := "ECDSA"
	keySize := "p224"
	privateKey, publicKey, err := pki.GenerateKeys(algo, keySize)
	if privateKey == "" {
		t.Errorf("Failed to generate private key for '%s' with key size of '%s'. %s", algo, keySize, err)
	}
	if publicKey == "" {
		t.Errorf("Failed to generate public key for '%s' with key size of '%s'. %s ", algo, keySize, err)
	}
	if err != nil {
		t.Errorf("Failed to generate public & private key for '%s' with key size of '%s'. %s", algo, keySize, err)
	}
}

func TestGenerateKeysECDSAKInvalidKeySize(t *testing.T) {
	algo := "ECDSA"
	keySize := "notReal"
	_, _, err := pki.GenerateKeys(algo, keySize)
	if !errorContains(err, "The valid key sizes for ECDSA keys are: p224, p256, p384, or p521") {
		t.Errorf("Key should not have been generated. %s", err)
	}
}

func TestGenerateKeysED25519(t *testing.T) {
	algo := "ED25519"
	keySize := ""
	privateKey, publicKey, err := pki.GenerateKeys(algo, keySize)
	if privateKey == "" {
		t.Errorf("Failed to generate private key for '%s' with key size of '%s'. %s", algo, keySize, err)
	}
	if publicKey == "" {
		t.Errorf("Failed to generate public key for '%s' with key size of '%s'. %s ", algo, keySize, err)
	}
	if err != nil {
		t.Errorf("Failed to generate public & private key for '%s' with key size of '%s'. %s", algo, keySize, err)
	}
}

func TestGenerateKeysInvalidAlgo(t *testing.T) {
	algo := "invalidAlgo"
	keySize := ""
	_, _, err := pki.GenerateKeys(algo, keySize)
	if !errorContains(err, "The provided key algorithm is not valid") {
		t.Errorf("Invalid error message. %s", err)
	}
}
