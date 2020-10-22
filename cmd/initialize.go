package cmd

import (
	"bytes"
	"fmt"
	"io"
	"log"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/cmd/helper"
	"github.com/spf13/cobra"
)

func initPolicy() io.Reader {
	return bytes.NewReader([]byte(`
- !host pki-service
- !policy
  id: pki
  owner: !host pki-service
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
		fmt.Printf("%v", resp)

		err = storage.InitConfig()
		if err != nil {
			log.Fatalf("Failed to Init the Conjur PKI Service. %s", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(initCMD)
}
