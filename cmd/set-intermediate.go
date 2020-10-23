package cmd

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/cmd/helper"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/httperror"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/pki"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
	"github.com/spf13/cobra"
)

var setIntermediateCmd = &cobra.Command{
	Use:   "set-intermediate",
	Short: "Set the intermediate certificate",
	Long: `Set the intermediate certificate.
	
	Example Usage:
	$ pkiaas set-intermediate  --cert-file /path/to/intermediate.pem`,
	Run: func(cmd *cobra.Command, args []string) {
		storage, err := helper.GetConjurStorageBackend()
		if err != nil {
			log.Fatalf("Failed to get the Conjur storage backend. %s", err)
		}

		content, err := ioutil.ReadFile(CertFile)
		if err != nil {
			log.Fatalf("Failed to read certificate located at %s. %s", CertFile, err)
		}

		req := types.PEMCertificate{
			Certificate: string(content),
		}

		httpErr := pki.SetIntermediateCertificate(req, storage)
		if httpErr != (httperror.HTTPError{}) {
			httpErr.JSON()
			os.Exit(1)
		}

		fmt.Printf("Intermediate CA certificate from %s successfully set.", CertFile)
	},
}

func init() {
	// Cert File
	setIntermediateCmd.Flags().StringVarP(&CertFile, certFileFlag, "c", "", "File path to the Intermediate Certificate")
	setIntermediateCmd.MarkFlagRequired(certFileFlag)

	rootCmd.AddCommand(setIntermediateCmd)
}
