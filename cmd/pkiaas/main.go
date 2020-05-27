package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/pkg/pkiaas"
)

func main() {
	router := mux.NewRouter().StrictSlash(true)
	fmt.Printf("Running at http://localhost:8080 - v%s", pkiaas.FullVersionName)
	log.Fatal(http.ListenAndServe(":8080", router))
}
