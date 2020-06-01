package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/pki"
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
		pki.GetCAHandler,
	},

	Route{
		"GetCAChain",
		strings.ToUpper("Get"),
		"/ca/chain",
		pki.GetCAChainHandler,
	},

	Route{
		"CreateCertificate",
		strings.ToUpper("Post"),
		"/certificate/create",
		pki.CreateCertHandler,
	},

	Route{
		"GetCertificate",
		strings.ToUpper("Get"),
		"/certificate/{serialNumber}",
		pki.GetCertHandler,
	},

	Route{
		"ListCertificates",
		strings.ToUpper("Get"),
		"/certificates",
		pki.ListCertsHandler,
	},

	Route{
		"Purge",
		strings.ToUpper("Post"),
		"/purge",
		pki.PurgeHandler,
	},

	Route{
		"RevokeCertificate",
		strings.ToUpper("Post"),
		"/certificate/revoke",
		pki.RevokeCertHandler,
	},

	Route{
		"SignCertificate",
		strings.ToUpper("Post"),
		"/certificate/sign",
		pki.SignCertHandler,
	},

	// Route{
	// 	"GetCRL",
	// 	strings.ToUpper("Get"),
	// 	"/crl",
	// 	pki.GetCRLHandler,
	// },

	Route{
		"PurgeCRL",
		strings.ToUpper("Post"),
		"/crl/purge",
		pki.PurgeCRLHandler,
	},

	Route{
		"CreateTemplate",
		strings.ToUpper("Post"),
		"/template/create",
		pki.CreateTemplateHandler,
	},

	Route{
		"DeleteTemplate",
		strings.ToUpper("Delete"),
		"/template/delete/{templateName}",
		pki.DeleteTemplateHandler,
	},

	Route{
		"GetTemplate",
		strings.ToUpper("Get"),
		"/template/{templateName}",
		pki.GetTemplateHandler,
	},

	Route{
		"ListTemplates",
		strings.ToUpper("Get"),
		"/templates",
		pki.ListTemplatesHandler,
	},

	Route{
		"ManageTemplate",
		strings.ToUpper("Put"),
		"/template/manage",
		pki.ManageTemplateHandler,
	},

	// Route{
	// 	"Health",
	// 	strings.ToUpper("Get"),
	// 	"/health",
	// 	TBD
	// },
}
