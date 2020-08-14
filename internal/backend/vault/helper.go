package vault

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/api"
)

func rootPath() string {
	return "pki-service/data"
}

func getDefaultKey() string {
	return "content"
}

func readSecretAndGetContent(client *api.Client, secretPath string, base64Decode bool) (string, error) {
	key := getDefaultKey()
	secret, err := client.Logical().Read(secretPath)
	if err != nil {
		return "", fmt.Errorf("Failed to retrieve signing certificate with variable id '%s' and key '%s'. %s", secretPath, key, err)
	}
	if secret == nil {
		return "", fmt.Errorf("Secret does not exist or has not been initilized")
	}

	data, ok := secret.Data["data"]
	if !ok {
		return "", fmt.Errorf("Failed to retrieve data from KV '%s' with key '%s'", secretPath, key)
	}
	if data == nil {
		return "", fmt.Errorf("Secret does not exist or has not been initilized")
	}

	value, ok := data.(map[string]interface{})["content"]
	if !ok {
		return "", fmt.Errorf("Failed to parse KV '%s' with key '%s'", secretPath, key)
	}

	if base64Decode {
		tmp, err := base64.StdEncoding.DecodeString(value.(string))
		if err != nil {
			return "", fmt.Errorf("Failed to base64 decode KV '%s' with key '%s'. %s", secretPath, key, err)
		}
		value = string(tmp)
	}

	return value.(string), nil
}

func ReadSecretAndGetContent(client *api.Client, secretPath string, base64Decode bool) (string, error) {
	return readSecretAndGetContent(client, secretPath, base64Decode)
}

func writeSecretContent(client *api.Client, secretPath string, base64Encode bool, value string) error {
	key := getDefaultKey()
	if base64Encode {
		value = base64.StdEncoding.EncodeToString([]byte(value))
	}

	secret := map[string]interface{}{key: value}
	data := map[string]interface{}{"data": secret}

	message, err := client.Logical().Write(secretPath, data)
	if err != nil {
		return fmt.Errorf("Failed to set KV '%s' and key '%s'. Message: %v. %s", secretPath, key, message, err)
	}
	return nil
}

func WriteSecretContent(client *api.Client, secretPath string, base64Encode bool, value string) error {
	return writeSecretContent(client, secretPath, base64Encode, value)
}

func listKVs(client *api.Client, secretPath string) ([]string, error) {
	var kvs []string
	secretPath = strings.ReplaceAll(secretPath, "/data/", "/metadata/")
	secret, err := client.Logical().List(secretPath)
	if err != nil {
		return kvs, fmt.Errorf("Failed to list templates. %s", err)
	}

	keys, ok := secret.Data["keys"]
	if !ok || keys == nil {
		return kvs, fmt.Errorf("Failed to retrieve keys from KV '%s'", secretPath)
	}

	keysList, ok := keys.([]interface{})
	if !ok || keysList == nil {
		return kvs, fmt.Errorf("Failed to retrieve keys from interface KV '%s'", secretPath)
	}

	keysStringList := make([]string, len(keysList))
	for i, k := range keysList {
		keysStringList[i] = k.(string)
	}

	return keysStringList, nil
}
