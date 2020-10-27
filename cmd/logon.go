package cmd

import (
	"fmt"
	"log"
	"syscall"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/cmd/helper"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	// Login ... Username to logon PAS REST API using
	Login string
	// Account ... AuthenticationType to be used to logon PAS REST API
	Account string
	// ApplianceURL ... BaseURL to send PAS REST API logon request to
	ApplianceURL string
	// CertFile ... SSL Certifictae file path
	CertFile string
	// InsecureTLS is a boolean value whether to verify TLS or not
	InsecureTLS bool
)

const (
	loginFlag        = "login"
	applianceURLFlag = "appliance-url"
	accountFlag      = "account"
	certFileFlag     = "cert-file"
	insecureFlag     = "ignore-untrusted-cert"
)

var logonCmd = &cobra.Command{
	Use:   "logon",
	Short: "Logon to Conjur API",
	Long: `Authenticate to the Conjur API.
	
	Example Usage:
	$ pkiaas logon -l $USERNAME -u https://conjur-master.company.local -a companyName`,
	Run: func(cmd *cobra.Command, args []string) {
		// Get secret value from STDIN
		fmt.Print("Enter password: ")
		byteSecretVal, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatalln("An error occurred trying to read password from " +
				"Stdin. Exiting...")
		}

		config := conjurapi.Config{
			Account:      Account,
			ApplianceURL: ApplianceURL,
			SSLCertPath:  CertFile,
		}
		loginPair := authn.LoginPair{
			Login:  Login,
			APIKey: string(byteSecretVal),
		}

		client, err := conjurapi.NewClientFromKey(config, loginPair)
		if err != nil {
			log.Fatalf("Failed to create Conjur client. %s", err)
		}

		apiKey, err := helper.Logon(client, Login, byteSecretVal)
		if err != nil {
			log.Fatalf("Failed to login to Conjur. %s", err)
		}

		loginPair = authn.LoginPair{
			Login:  Login,
			APIKey: string(apiKey),
		}

		accessToken, err := client.Authenticate(loginPair)
		if err != nil {
			log.Fatalf("Failed to retrieve access token from Conjur. %s", err)
		}

		client, err = conjurapi.NewClientFromToken(config, string(accessToken))
		if err != nil {
			log.Fatalf("Failed to create Conjur client with access token. %s", err)
		}

		credObj := helper.ConjurCredentials{
			ApplianceURL: ApplianceURL,
			Account:      Account,
			CertFile:     CertFile,
			Login:        Login,
			AccessToken:  string(accessToken),
		}

		err = helper.SetConfig(credObj)
		if err != nil {
			log.Fatalf("Failed to write Conjur credentials to a file. %s", err)
		}

		fmt.Printf("Successfully logged onto Conjur as login '%s'.\n", Login)
	},
}

func init() {
	// Appliance
	logonCmd.Flags().StringVarP(&ApplianceURL, applianceURLFlag, "u", "", "Conjur appliance URL")
	logonCmd.MarkFlagRequired(applianceURLFlag)
	// Account
	logonCmd.Flags().StringVarP(&Account, accountFlag, "a", "", "Conjur account")
	logonCmd.MarkFlagRequired(accountFlag)
	// Login
	logonCmd.Flags().StringVarP(&Login, loginFlag, "l", "", "Login for Conjur")
	logonCmd.MarkFlagRequired(loginFlag)

	// Optional cert File
	logonCmd.Flags().StringVarP(&CertFile, certFileFlag, "c", "", "Path to the Conjur certificate chain file")
	logonCmd.Flags().BoolVarP(&InsecureTLS, insecureFlag, "i", false, "If detected, TLS will not be verified")

	rootCmd.AddCommand(logonCmd)
}
