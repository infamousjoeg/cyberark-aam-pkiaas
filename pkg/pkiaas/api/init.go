package api

import (
	"flag"
	"fmt"
	"os"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend/conjur"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/pkg/pkiaas"
)

var storage backend.Storage

func init() {
	initConfig := flag.Bool("i", false, "Load init policy for service")
	version := flag.Bool("v", false, "Display current version")

	flag.Parse()

	// -v flag detected
	if *version {
		fmt.Printf("pkiaas v%s\n", pkiaas.FullVersionName)
		os.Exit(1)
	}

	pkiclient, err := conjur.NewFromDefaults()
	if err != nil {
		panic("Error initializing PKI backend: " + err.Error())
	}

	// -i flag detected
	if *initConfig {
		err = pkiclient.InitConfig()
		if err != nil {
			panic("Error initializing PKI configuration: " + err.Error())
		}
	}

	storage = pkiclient
	// storage = dummy.Dummy{}
}
