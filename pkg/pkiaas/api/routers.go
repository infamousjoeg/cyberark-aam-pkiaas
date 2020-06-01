package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// Route struct
type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

// Routes splice
type Routes []Route

// NewRouter //
// For handling routing through API engine
func NewRouter() *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	for _, route := range routes {
		var handler http.Handler
		handler = route.HandlerFunc
		handler = Logger(handler, route.Name)

		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(handler)
	}

	return router
}

///////////////////////
// GET ROUTES START //
//////////////////////

// Index route //
// Returns confirmation message on successful GET of /
func Index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Successful GET /")
}

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

// GetCertificate route //
// Returns signed certificate based on serial number given
func GetCertificate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serialNumber := vars["serialNumber"]
	fmt.Fprintf(w, "Successful GET /certificate/%s", serialNumber)
}

// ListCertificates route //
// Returns all certificates signed by the CA
func ListCertificates(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Successful GET /certificates")
}

// GetCRL route //
// Returns the current Certificate Revokation List (CRL)
func GetCRL(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Successful GET /crl")
}

// GetTemplate route //
// Returns a template from Conjur service based on template name
func GetTemplate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	templateName := vars["templateName"]
	fmt.Fprintf(w, "Successful GET /template/%s", templateName)
}

// ListTemplates route //
// Returns a list of templates created in the Conjur service
func ListTemplates(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Successful GET /templates")
}

////////////////////////
// POST ROUTES START //
///////////////////////

var routes = Routes{
	Route{
		"Index",
		strings.ToUpper("Get"),
		"/",
		Index,
	},

	Route{
		"GetCA",
		strings.ToUpper("Get"),
		"/ca/certificate",
		GetCA,
	},

	Route{
		"GetCAChain",
		strings.ToUpper("Get"),
		"/ca/chain",
		GetCAChain,
	},

	// Route{
	// 	"CheckCertificate",
	// 	strings.ToUpper("Post"),
	// 	"/certificate/check/{serialNumber}",
	// 	CheckCertificate,
	// },

	// Route{
	// 	"CreateCertificate",
	// 	strings.ToUpper("Post"),
	// 	"/certificate/create",
	// 	CreateCertificate,
	// },

	Route{
		"GetCertificate",
		strings.ToUpper("Get"),
		"/certificate/{serialNumber}",
		GetCertificate,
	},

	Route{
		"ListCertificates",
		strings.ToUpper("Get"),
		"/certificates",
		ListCertificates,
	},

	// Route{
	// 	"PurgeCertificates",
	// 	strings.ToUpper("Post"),
	// 	"/certificates/purge/{timeBuffer}",
	// 	PurgeCertificates,
	// },

	// Route{
	// 	"RevokeCertificate",
	// 	strings.ToUpper("Delete"),
	// 	"/certificate/revoke/{serialNumber}",
	// 	RevokeCertificate,
	// },

	// Route{
	// 	"SignCertificate",
	// 	strings.ToUpper("Post"),
	// 	"/certificate/sign",
	// 	SignCertificate,
	// },

	Route{
		"GetCRL",
		strings.ToUpper("Get"),
		"/crl",
		GetCRL,
	},

	// Route{
	// 	"PurgeCRL",
	// 	strings.ToUpper("Post"),
	// 	"/crl/purge/{timeBuffer}",
	// 	PurgeCRL,
	// },

	// Route{
	// 	"CreateTemplate",
	// 	strings.ToUpper("Post"),
	// 	"/template/create",
	// 	CreateTemplate,
	// },

	// Route{
	// 	"DeleteTemplate",
	// 	strings.ToUpper("Delete"),
	// 	"/template/delete/{templateName}",
	// 	DeleteTemplate,
	// },

	Route{
		"GetTemplate",
		strings.ToUpper("Get"),
		"/template/{templateName}",
		GetTemplate,
	},

	Route{
		"ListTemplates",
		strings.ToUpper("Get"),
		"/templates",
		ListTemplates,
	},

	// Route{
	// 	"ManageTemplate",
	// 	strings.ToUpper("Put"),
	// 	"/template/manage",
	// 	ManageTemplate,
	// },
}
