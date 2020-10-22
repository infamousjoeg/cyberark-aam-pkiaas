package cmd

import (
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend/conjur"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend/vault"
	"github.com/spf13/cobra"
)

var storage backend.Storage

func getPort() string {
	p := os.Getenv("PORT")
	if p != "" {
		return ":" + p
	}
	return ":8080"
}

var serverCMD = &cobra.Command{
	Use:   "server",
	Short: "Start the PKI Service server",
	Long: `Start the PKI Service server.
	
	Example Usage:
	$ pkiaas server -c pki1-service.company.local`,
	Run: func(cmd *cobra.Command, args []string) {

		vaultBackend := strings.ToLower(os.Getenv("PKI_VAULT_BACKEND"))
		var err error
		if vaultBackend == "yes" || vaultBackend == "true" {
			storage, err = vault.NewFromDefaults()
		} else {
			storage, err = conjur.NewFromDefaults()
		}
		if err != nil {
			panic("Error initializing PKI backend: " + err.Error())
		}

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
