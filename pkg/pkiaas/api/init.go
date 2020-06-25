package api

import (
	"flag"
	"fmt"
	"os"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend/conjur"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/pkg/pkiaas"
)

func init() {
	version := flag.Bool("v", false, "Display current version")

	flag.Parse()

	if *version {
		fmt.Printf("pkiaas v%s\n", pkiaas.FullVersionName)
		os.Exit(1)
	}
	pkiclient, err := conjur.NewFromDefaults()
	if err != nil {
		panic("Error initializing PKI backend: " + err.Error())
	}

	err = pkiclient.InitConfig()
	if err != nil {
		panic("Error initializing PKI configuration: " + err.Error())
	}
	backend.Backend = pkiclient
	//	backend.Backend = dummy.Dummy{}
}
