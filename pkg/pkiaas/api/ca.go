package api

import (
	"fmt"
	"net/http"
)

// GetCA route //
// Returns CA certificate
func GetCA(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Successful GET /ca/certificate")
}

// GetCAChain route //
// Returns CA certificate chain
func GetCAChain(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Successful GET /ca/chain")
}
