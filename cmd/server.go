package cmd

import (
	"net/http"
	"os"
	"strings"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend/conjur"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend/vault"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/httperror"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/pki"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/pkg/log"

	"github.com/spf13/cobra"
)

var storage backend.Storage

const (
	certFile = "/etc/ssl/server.pem"
	keyFile  = "/etc/ssl/server.key"
	portFlag = "port"
)

// Gets the port number supplied by end-user or else defaults to 443
func getPort() string {
	if Port != "" {
		return ":" + Port
	}
	return ":443"
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func createServerTLS() {
	// If file already exists use them
	if fileExists(certFile) && fileExists(keyFile) {
		return
	}

	log.Info("Generating server certificate from template 'pki-service'")

	certReq := types.CreateCertReq{
		TemplateName: "pki-service",
		CommonName:   CommonName,
		AltNames:     AltNames,
	}

	certResp, httpErr := pki.CreateCert(certReq, storage)
	if httpErr != (httperror.HTTPError{}) {
		httpErr.JSON()
		os.Exit(1)
	}

	pemCert := certResp.Certificate
	pemPrivKey := certResp.PrivateKey
	certFile, err := os.Create(certFile)
	if err != nil {
		log.Error("Error creating server TLS certificate file: " + err.Error())
	}

	_, err = certFile.Write([]byte(pemCert))
	if err != nil {
		log.Error("Error writing to server TLS certificate file: " + err.Error())
	}

	keyFile, err := os.Create(keyFile)
	if err != nil {
		log.Error("Error creating server private key file: " + err.Error())
	}

	_, err = keyFile.Write([]byte(pemPrivKey))
	if err != nil {
		log.Error("Error writing to server private key file: " + err.Error())
	}

	if err != nil {
		os.Exit(1)
	}
}

var serverCMD = &cobra.Command{
	Use:   "server",
	Short: "Start the PKI Service server",
	Long: `Start the PKI Service server.
	
	Example Usage:
	$ pkiaas server -c pki1-service.company.local -a pki-altname.company.local`,
	Run: func(cmd *cobra.Command, args []string) {
		vaultBackend := strings.ToLower(os.Getenv("PKI_VAULT_BACKEND"))

		var err error
		if vaultBackend == "yes" || vaultBackend == "true" {
			storage, err = vault.NewFromDefaults()
		} else {
			os.Setenv("CONJUR_APPLIANCE_URL", ApplianceURL)
			os.Setenv("CONJUR_ACCOUNT", Account)
			os.Setenv("CONJUR_AUTHN_LOGIN", Login)
			if CertFile != "" {
				os.Setenv("CONJUR_CERT_FILE", CertFile)
			}

			storage, err = conjur.NewFromDefaults()
		}

		if err != nil {
			log.Error("Error initializing PKI backend. %s", err.Error())
			os.Exit(1)
		}

		createServerTLS()

		log.Info("Server started")
		router := NewRouter()
		port := getPort()
		log.Error("%s", http.ListenAndServeTLS(port, certFile, keyFile, router))
		os.Exit(1)
	},
}

func mandatoryFlagWithEnvVar(cmd cobra.Command, flag string, envVar string) {
	if envVar == "" {
		cmd.MarkFlagRequired(flag)
	}
}

var (
	// Port of the PKI Service
	Port string
)

func init() {
	applianceURLEnv := os.Getenv("CONJUR_APPLIANCE_URL")
	accountEnv := os.Getenv("CONJUR_ACCOUNT")
	loginEnv := os.Getenv("CONJUR_AUTHN_LOGIN")
	certFileEnv := os.Getenv("CONJUR_CERT_FILE")
	portEnv := os.Getenv("PORT")

	// Common Name
	serverCMD.Flags().StringVarP(&CommonName, commonNameFlag, "c", "", "Common name for the PKI Service")
	serverCMD.MarkFlagRequired(commonNameFlag)

	// Appliance
	serverCMD.Flags().StringVarP(&ApplianceURL, applianceURLFlag, "u", applianceURLEnv, "Conjur appliance URL. Environment variable equivalent 'CONJUR_APPLIANCE_URL'")
	mandatoryFlagWithEnvVar(*serverCMD, applianceURLFlag, applianceURLEnv)

	// Account
	serverCMD.Flags().StringVarP(&Account, accountFlag, "a", accountEnv, "Conjur account. Environment variable equivalent 'CONJUR_ACCOUNT'")
	mandatoryFlagWithEnvVar(*serverCMD, accountFlag, accountEnv)

	// Login
	serverCMD.Flags().StringVarP(&Login, loginFlag, "l", loginEnv, "Login for Conjur. Environment variable equivalent 'CONJUR_AUTHN_LOGIN'")
	mandatoryFlagWithEnvVar(*serverCMD, loginFlag, loginEnv)

	// Optional cert File
	serverCMD.Flags().StringVarP(&CertFile, certFileFlag, "f", certFileEnv, "Path to the Conjur certificate chain file. Environment variable equivalent 'CONJUR_CERT_FILE'")

	// Optional Port
	serverCMD.Flags().StringVarP(&Port, portFlag, "p", portEnv, "Port of the PKI Service. Environment variable equivalent 'PORT'")

	// Optional AltNames
	serverCMD.Flags().StringSliceVarP(&AltNames, altNamesFlag, "n", []string{}, "Alternative names for the PKI Service")

	rootCmd.AddCommand(serverCMD)
}
