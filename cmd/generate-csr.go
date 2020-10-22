package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/cmd/helper"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/httperror"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/pki"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/types"
	"github.com/spf13/cobra"
)

var generateCSRCmd = &cobra.Command{
	Use:   "generate-csr",
	Short: "Generate a CSR for the intermediate certificate",
	Long: `Generate a CSR for the intermediate certificate.
	
	Example Usage:
	$ pkiaas generate-csr  --common-name pki.company.local --key-algo rsa --key-bits 2048 --max-ttl 1440`,
	Run: func(cmd *cobra.Command, args []string) {
		storage, err := helper.GetConjurStorageBackend()
		if err != nil {
			log.Fatalf("Failed to get the Conjur storage backend. %s", err)
		}

		// Genertae the intermediate CSR
		req := types.IntermediateRequest{
			CommonName: CommonName,
			KeyAlgo:    KeyAlgo,
			KeyBits:    KeyBits,
			MaxTTL:     MaxTTL,
			AltNames:   AltNames,
		}

		pem, httpErr := pki.GenerateIntermediate(req, SelfSigned, storage)
		if httpErr != (httperror.HTTPError{}) {
			httpErr.JSON()
			os.Exit(1)
		}

		if SelfSigned {
			fmt.Print(pem.SelfSignedCert)
			return
		}

		fmt.Print(pem.CSR)
	},
}

var (
	CommonName string
	KeyAlgo    string
	KeyBits    string
	MaxTTL     int64
	AltNames   []string
	SelfSigned bool
)

const (
	commonNameFlag = "common-name"
	keyAlgoFlag    = "key-algo"
	keyBitsFlag    = "key-bits"
	maxTTLFlag     = "max-ttl"
	altNamesFlag   = "alt-names"
	selfSignedFlag = "self-signed"
)

func init() {
	// Common Name
	generateCSRCmd.Flags().StringVarP(&CommonName, commonNameFlag, "c", "", "Common name of the Intermediate Certificate")
	generateCSRCmd.MarkFlagRequired(commonNameFlag)

	// Key Algo
	generateCSRCmd.Flags().StringVarP(&KeyAlgo, keyAlgoFlag, "k", "", "Key algo for the Intermediate Certificate")
	generateCSRCmd.MarkFlagRequired(keyAlgoFlag)

	// Key Bits
	generateCSRCmd.Flags().StringVarP(&KeyBits, keyBitsFlag, "b", "", "Key bits for the Intermediate Certificate")
	generateCSRCmd.MarkFlagRequired(keyBitsFlag)

	// Max TTL
	generateCSRCmd.Flags().Int64VarP(&MaxTTL, maxTTLFlag, "m", 1440, "Max time to live for all certificates generated from the PKI Service")
	generateCSRCmd.MarkFlagRequired(maxTTLFlag)

	// AltNames
	generateCSRCmd.Flags().StringSliceVarP(&AltNames, altNamesFlag, "a", []string{}, "Alternative names for the Intermediate Certificate")

	// Self Signed
	generateCSRCmd.Flags().BoolVarP(&SelfSigned, selfSignedFlag, "", false, "Use a Self signed certificate as Intermediate for the PKI service. ONLY USE FOR POC AND DEVELOPMENT!")

	rootCmd.AddCommand(generateCSRCmd)
}
