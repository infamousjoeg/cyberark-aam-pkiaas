package conjur_test

import (
	b64 "encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend/conjur"
)

func assertErrorContains(t *testing.T, err error, contain string) {
	if !strings.Contains(err.Error(), contain) {
		t.Errorf("Incorrect error, should contain '%s' but is '%s'", contain, err)
	}
}

func defaultAccessControl() conjur.AccessControl {
	client, _ := conjur.NewDefaultConjurClient()
	accessControl := conjur.NewAccessFromDefaults(client.GetConfig(), "pki")
	return accessControl
}

func getValidAccessToken(t *testing.T) string {
	client, _ := conjur.NewDefaultConjurClient()
	config := client.GetConfig()
	apiKey := os.Getenv("CONJUR_AUTHN_API_KEY")
	hostname := strings.ReplaceAll(os.Getenv("CONJUR_AUTHN_LOGIN"), "/", "%2f")
	response, err := client.GetHttpClient().Post("https://conjur-master/authn/"+config.Account+"/"+hostname+"/authenticate", "application/json", strings.NewReader(apiKey))
	assertNoError(t, err)
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		encodedJWT := b64.StdEncoding.EncodeToString(bodyBytes)
		accessToken := fmt.Sprintf("Token token=\"%s\"", encodedJWT)
		return accessToken
	}

	t.Errorf("Failed to authenticate. Recieved status code %v", response.StatusCode)
	return ""
}

func TestAuthenticate(t *testing.T) {
	accessControl := defaultAccessControl()
	accessToken := getValidAccessToken(t)
	err := accessControl.Authenticate(accessToken)
	assertNoError(t, err)
}

func TestInvalidAuthenticate(t *testing.T) {
	accessControl := defaultAccessControl()
	accessToken := ""
	err := accessControl.Authenticate(accessToken)
	assertErrorContains(t, err, "Unable to unmarshal token")
}

func TestExpiredAuthenticate(t *testing.T) {
	accessControl := defaultAccessControl()
	accessToken := `Token token="eyJwcm90ZWN0ZWQiOiJleUpoYkdjaU9pSmpiMjVxZFhJdWIzSm5MM05zYjNOcGJHOHZkaklpTENKcmFXUWlPaUkyWVRZME9XWmlOak16TWprMk1qYzFOV014TlRCbU5tRmtaV0V6TlRNMVl5SjkiLCJwYXlsb2FkIjoiZXlKemRXSWlPaUpvYjNOMEwzQnJhUzFoWkcxcGJpSXNJbWxoZENJNk1UVTVNelUxTVRReU5YMD0iLCJzaWduYXR1cmUiOiJld0ptN3dzRWpIXzJKV05WRGlFd1JsVHBSM0cyNUtVR3Q1aG5NN1ExYlVOc2hyMnMwTFUzQ2dBakRfeE9uWkFyMTBmY1dCeWlvZ3BFQmt0b3RUelp5d2JQcmFsQlpFcDduQlFuRkhDRFpXeXd3ZXpyS0xmR2xoQTJjQ0p3SGUyalVSN0pULTFmOW53cW1CSXBoY3NUSHZWdElUXzlHN0xUZ0RncTRrNXpMeGtvZE1wTG5NdUlxZmJzVWhBT25JSURGenFOLU5uS1RrN1BnQ25pQzRiNWN4MEdrWVJlS01RbEZUMFJPczRmUEFNd3hKTHNaMXVrR3pxZXRsWGlCSVIyU29WYWRyRG9PeVJTLXJiWmVYZUg2aEoyaU9GNkZnUHVzckFZZ2lmQ3Z5eXdkcUJvaktlTDM3YVhudHVpQ0FkNm85TjZwV3lzd1NLa1BESUFDR0FEN05DNnpwX2dJZkhVQURfVTZ3UVFLcWNVbVlfUWpQMW01alBvLXJQaVFIOVMifQ=="`
	err := accessControl.Authenticate(accessToken)
	assertErrorContains(t, err, "Could not check the permissions. Permission check failed with HTTP status 401")
}
