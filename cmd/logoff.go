package cmd

import (
	"log"
	"os"

	"github.com/spf13/cobra"
)

var logoffCmd = &cobra.Command{
	Use:   "logoff",
	Short: "Logoff of the Conjur API",
	Long: `Logoff of the Conjur API.
	
	Example Usage:
	$ pkiaas logoff`,
	Run: func(cmd *cobra.Command, args []string) {
		// Get user home directory
		userHome, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("Could not read user home directory for OS. %s", err)
		}

		// Remove the config file written to local file system
		fullPath := userHome + "/.conjur"
		err = os.Remove(fullPath)
		if err != nil {
			log.Fatalf("Failed to remove configuration file at %s/.conjur. %s", userHome, err)
		}
	},
}

func init() {
	rootCmd.AddCommand(logoffCmd)
}
