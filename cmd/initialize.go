package cmd

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/cmd/helper"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/httperror"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/pki"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
	"github.com/spf13/cobra"
)

func initPolicy() io.Reader {
	return bytes.NewReader([]byte(`
- !group pki-service
- !policy
  id: pki
  owner: !group pki-service
  body:
    - !group admin
`))
}

var initCMD = &cobra.Command{
	Use:   "init",
	Short: "Initialize the Conjur backend to use a PKI service",
	Long: `Initialize the Conjur backend to use a PKI service.
	
	Example Usage:
	$ pkiaas init`,
	Run: func(cmd *cobra.Command, args []string) {
		client, err := helper.GetClient()
		if err != nil {
			log.Fatalf("Failed to get Conjur Client. Make sure you logged in recently. %s", err)
		}
		storage, err := helper.GetConjurStorageBackend()
		if err != nil {
			log.Fatalf("Failed to get the Conjur storafe backend. %s", err)
		}

		resp, err := client.LoadPolicy(conjurapi.PolicyModePost, "root", initPolicy())
		if err != nil {
			log.Fatalf("Failed to load init Conjur policy. %v. %s", resp, err)
		}

		err = storage.InitConfig()
		if err != nil {
			log.Fatalf("Failed to Init the Conjur PKI Service. %s", err)
		}

		template := types.Template{
			TemplateName: "pki-service",
			KeyAlgo:      "rsa",
			KeyBits:      "2048",
			MaxTTL:       43200,
		}

		httpErr := pki.CreateTemplate(template, storage)
		if httpErr != (httperror.HTTPError{}) {
			httpErr.JSON()
			os.Exit(1)
		}

		fmt.Printf("%v\n", resp)
		fmt.Printf("Add your PKI service host to the '%s' group.", "pki-service")
	},
}

func init() {
	rootCmd.AddCommand(initCMD)
}
