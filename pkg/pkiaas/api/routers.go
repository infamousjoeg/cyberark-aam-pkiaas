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

// NewRouter handles routing from the API package to PKI package
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

// Index returns confirmation message on successful GET request to /
func Index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Successful GET /")
}

// GetHealthHandler returns OK if this application is running
func GetHealthHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "OK")
}

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
		GetCAHandler,
	},

	Route{
		"GetCAChain",
		strings.ToUpper("Get"),
		"/ca/chain",
		GetCAChainHandler,
	},

	Route{
		"CreateCertificate",
		strings.ToUpper("Post"),
		"/certificate/create",
		CreateCertHandler,
	},

	Route{
		"GetCertificate",
		strings.ToUpper("Get"),
		"/certificate/{serialNumber}",
		GetCertHandler,
	},

	Route{
		"ListCertificates",
		strings.ToUpper("Get"),
		"/certificates",
		ListCertsHandler,
	},

	Route{
		"Purge",
		strings.ToUpper("Post"),
		"/purge",
		PurgeHandler,
	},

	Route{
		"RevokeCertificate",
		strings.ToUpper("Post"),
		"/certificate/revoke",
		RevokeCertHandler,
	},

	Route{
		"SignCertificate",
		strings.ToUpper("Post"),
		"/certificate/sign",
		SignCertHandler,
	},

	Route{
		"GetCRL",
		strings.ToUpper("Get"),
		"/crl",
		GetCRLHandler,
	},

	Route{
		"PurgeCRL",
		strings.ToUpper("Post"),
		"/crl/purge",
		PurgeCRLHandler,
	},

	Route{
		"CreateTemplate",
		strings.ToUpper("Post"),
		"/template/create",
		CreateTemplateHandler,
	},

	Route{
		"DeleteTemplate",
		strings.ToUpper("Delete"),
		"/template/delete/{templateName}",
		DeleteTemplateHandler,
	},

	Route{
		"GetTemplate",
		strings.ToUpper("Get"),
		"/template/{templateName}",
		GetTemplateHandler,
	},

	Route{
		"ListTemplates",
		strings.ToUpper("Get"),
		"/templates",
		ListTemplatesHandler,
	},

	Route{
		"ManageTemplate",
		strings.ToUpper("Put"),
		"/template/manage",
		ManageTemplateHandler,
	},

	Route{
		"GenerateIntermediateCSR",
		strings.ToUpper("Post"),
		"/ca/generate",
		GenerateIntermediateCSRHandler,
	},

	Route{
		"SetIntermediateCertificate",
		strings.ToUpper("Post"),
		"/ca/set",
		SetIntermediateCertHandler,
	},

	Route{
		"SetCAChain",
		strings.ToUpper("Post"),
		"/ca/chain/set",
		SetCAChainHandler,
	},

	Route{
		"Health",
		strings.ToUpper("Get"),
		"/health",
		GetHealthHandler,
	},
}
