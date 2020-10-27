package helper

import (
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend/conjur"
)

//ConjurCredentials ...
type ConjurCredentials struct {
	ApplianceURL string `json:"appliance_url"`
	Account      string `json:"account"`
	Login        string `json:"login"`
	AccessToken  string `json:"access_token"`
	CertFile     string `json:"cert_file"`
}

// GetConjurStorageBackend ...
func GetConjurStorageBackend() (conjur.StorageBackend, error) {
	// init the conjur backend
	policyBranch := "pki"
	client, err := GetClient()
	if err != nil {
		return conjur.StorageBackend{}, err
	}
	storage := conjur.NewConjurPki(client, policyBranch, conjur.NewDefaultTemplates(), conjur.NewAccessFromDefaults(client.GetConfig(), policyBranch), "master")
	return storage, nil
}

// SetConfig Sets the ConjurCredentials object into a file
func SetConfig(cred ConjurCredentials) error {
	// Get user home directory
	userHome, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("Failed to retrieve home directory. %s", err)
	}

	// Create config file in user home directory
	dataFile, err := os.Create(userHome + "/.conjur")
	if err != nil {
		return fmt.Errorf("Could not create configuration file at %s/.conjur. %s", userHome, err)
	}

	// serialize the data
	dataEncoder := gob.NewEncoder(dataFile)
	err = dataEncoder.Encode(&cred)
	if err != nil {
		return fmt.Errorf("Failed to encode the Conjur client. %s", err)
	}

	err = dataFile.Close()
	if err != nil {
		return fmt.Errorf("Failed to close the Conjur client file. %s", err)
	}

	return nil
}

// GetClient Get the conjurapi.Client from the file that was written by SetConfig()
func GetClient() (*conjurapi.Client, error) {
	var creds *ConjurCredentials

	// Get user home directory
	userHome, err := os.UserHomeDir()
	if err != nil {
		return &conjurapi.Client{}, fmt.Errorf("Failed to retrieve home directory. %s", err)
	}

	credFile := userHome + "/.conjur"

	// open data file
	dataFile, err := os.Open(credFile)
	if err != nil {
		return &conjurapi.Client{}, fmt.Errorf("Failed to retrieve configuration file at '%s'. %s", credFile, err)
	}

	dataDecoder := gob.NewDecoder(dataFile)
	err = dataDecoder.Decode(&creds)
	if err != nil {
		return &conjurapi.Client{}, fmt.Errorf("Failed to decode configuration file at .cybr/config. %s", err)
	}
	dataFile.Close()

	config := conjurapi.Config{
		Account:      creds.Account,
		ApplianceURL: creds.ApplianceURL,
		SSLCertPath:  creds.CertFile,
	}
	client, err := conjurapi.NewClientFromToken(config, creds.AccessToken)
	return client, err

}

// Logon to the Conjur. Will return a API key
func Logon(c *conjurapi.Client, login string, password []byte) ([]byte, error) {
	client := c.GetHttpClient()
	url := fmt.Sprintf("%s/authn/%s/login", c.GetConfig().ApplianceURL, c.GetConfig().Account)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to make new HTTP request. %s", err)
	}
	authorizationValue := base64.RawStdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", login, string(password))))
	authorizationValue = "Basic " + authorizationValue
	req.Header.Add("Authorization", authorizationValue)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Failed to establish connection to Conjur. %s", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Recieved status code '%v' when attempting to login to Conjur", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Failed to read API key from Conjur response. %s", err)
	}

	return body, nil
}
