package cmd

import (
	"log"
	"net/http"
	"os"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/httperror"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/pki"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"

	"github.com/spf13/cobra"
)

var storage backend.Storage

var cert string = "/etc/ssl/server.pem"
var key string = "/etc/ssl/server.key"

// Gets the port number supplied by end-user or else defaults to 443
func getPort() string {
	p := os.Getenv("PORT")
	if p != "" {
		return ":" + p
	}
	return ":443"
}

func createServerTLS() {
	// If cert and key exists, just return
	if _, err := os.Stat("/etc/ssl/server.key"); err == nil {
		return
	} else if os.IsNotExist(err) {
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
		certFile, err := os.Create(cert)
		if err != nil {
			log.Fatal("Error creating server TLS self-signed certificate file: " + err.Error())
		}

		_, err = certFile.Write([]byte(pemCert))
		if err != nil {
			log.Fatal("Error writing to server TLS self-signed certificate file: " + err.Error())
		}

		keyFile, err := os.Create(key)
		if err != nil {
			log.Fatal("Error creating server private key file: " + err.Error())
		}

		_, err = keyFile.Write([]byte(pemPrivKey))
		if err != nil {
			log.Fatal("Error writing to server private key file: " + err.Error())
		}
	} else {
		log.Fatal("Unknown error reading /etc/ssl directory.")
	}
}

var serverCMD = &cobra.Command{
	Use:   "server",
	Short: "Start the PKI Service server",
	Long: `Start the PKI Service server.
	
	Example Usage:
	$ pkiaas server -c pki1-service.company.local -a pki-altname.company.local`,
	Run: func(cmd *cobra.Command, args []string) {
		createServerTLS()

		log.Printf("Server started")
		router := NewRouter()
		port := getPort()
		log.Fatal(http.ListenAndServe(port, router))
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
