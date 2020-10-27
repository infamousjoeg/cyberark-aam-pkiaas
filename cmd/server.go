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
)

// Gets the port number supplied by end-user or else defaults to 443
func getPort() string {
	p := os.Getenv("PORT")
	if p != "" {
		return ":" + p
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

func init() {
	// Common Name
	serverCMD.Flags().StringVarP(&CommonName, commonNameFlag, "c", "", "Common name for the PKI Service")
	serverCMD.MarkFlagRequired(commonNameFlag)

	// AltNames
	serverCMD.Flags().StringSliceVarP(&AltNames, altNamesFlag, "a", []string{}, "Alternative names for the PKI Service")

	rootCmd.AddCommand(serverCMD)
}
