package api

import (
	"fmt"
	"net/http"
)

// GetCRL route //
// Returns the current Certificate Revokation List (CRL)
func GetCRL(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Successful GET /crl")
}
