package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/infamousjoeg/cyberark-aam-pkiaas/pkg/pkiaas"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/pkg/pkiaas/api"
)

func getPort() string {
	p := os.Getenv("PORT")
	if p != "" {
		return ":" + p
	}
	return ":8080"
}

func main() {
	version := flag.Bool("v", false, "Display current version")

	flag.Parse()

	if *version {
		fmt.Printf("pkiaas v%s\n", pkiaas.FullVersionName)
		os.Exit(1)
	}

	log.Printf("Server started")

	router := api.NewRouter()

	port := getPort()
	log.Fatal(http.ListenAndServe(port, router))
}
