package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend/conjur"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/backend/vault"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/pkg/pkiaas"
)

var storage backend.Storage

func init() {
	version := flag.Bool("v", false, "Display current version")

	flag.Parse()

	// -v flag detected
	if *version {
		fmt.Printf("pkiaas v%s\n", pkiaas.FullVersionName)
		os.Exit(1)
	}

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

	err = storage.InitConfig()
	if err != nil {
		panic("Error initializing PKI configuration: " + err.Error())
	}
}
