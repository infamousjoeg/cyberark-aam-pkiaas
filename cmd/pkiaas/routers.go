package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/pkg/pkiaas/api"
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

// HandlerContext Provides the storage backend to the handler functions via a context
func handlerContext(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		context.Set(r, "Storage", storage)
		h.ServeHTTP(w, r)
	})
}

// NewRouter handles routing from the API package to PKI package
func NewRouter() *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	for _, route := range routes {

		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(handlerContext(route.HandlerFunc))
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
		api.GetCAHandler,
	},

	Route{
		"GetCAChain",
		strings.ToUpper("Get"),
		"/ca/chain",
		api.GetCAChainHandler,
	},

	Route{
		"CreateCertificate",
		strings.ToUpper("Post"),
		"/certificate/create",
		api.CreateCertHandler,
	},

	Route{
		"GetCertificate",
		strings.ToUpper("Get"),
		"/certificate/{serialNumber}",
		api.GetCertHandler,
	},

	Route{
		"ListCertificates",
		strings.ToUpper("Get"),
		"/certificates",
		api.ListCertsHandler,
	},

	Route{
		"Purge",
		strings.ToUpper("Post"),
		"/purge",
		api.PurgeHandler,
	},

	Route{
		"RevokeCertificate",
		strings.ToUpper("Post"),
		"/certificate/revoke",
		api.RevokeCertHandler,
	},

	Route{
		"SignCertificate",
		strings.ToUpper("Post"),
		"/certificate/sign",
		api.SignCertHandler,
	},

	Route{
		"GetCRL",
		strings.ToUpper("Get"),
		"/crl",
		api.GetCRLHandler,
	},

	Route{
		"PurgeCRL",
		strings.ToUpper("Post"),
		"/crl/purge",
		api.PurgeCRLHandler,
	},

	Route{
		"CreateTemplate",
		strings.ToUpper("Post"),
		"/template/create",
		api.CreateTemplateHandler,
	},

	Route{
		"DeleteTemplate",
		strings.ToUpper("Delete"),
		"/template/delete/{templateName}",
		api.DeleteTemplateHandler,
	},

	Route{
		"GetTemplate",
		strings.ToUpper("Get"),
		"/template/{templateName}",
		api.GetTemplateHandler,
	},

	Route{
		"ListTemplates",
		strings.ToUpper("Get"),
		"/templates",
		api.ListTemplatesHandler,
	},

	Route{
		"ManageTemplate",
		strings.ToUpper("Put"),
		"/template/manage",
		api.ManageTemplateHandler,
	},

	Route{
		"GenerateIntermediateCSR",
		strings.ToUpper("Post"),
		"/ca/generate",
		api.GenerateIntermediateHandler,
	},

	Route{
		"GenerateSelfSigned",
		strings.ToUpper("Post"),
		"/ca/generate/selfsigned",
		api.GenerateIntermediateHandler,
	},

	Route{
		"SetIntermediateCertificate",
		strings.ToUpper("Post"),
		"/ca/set",
		api.SetIntermediateCertHandler,
	},

	Route{
		"SetCAChain",
		strings.ToUpper("Post"),
		"/ca/chain/set",
		api.SetCAChainHandler,
	},

	Route{
		"CreateSSHTemplate",
		strings.ToUpper("Post"),
		"/ssh/template",
		api.CreateSSHTemplateHandler,
	},

	Route{
		"GetSSHTemplate",
		strings.ToUpper("Get"),
		"/ssh/template/{templateName}",
		api.GetSSHTemplateHandler,
	},

	Route{
		"ListSSHTemplates",
		strings.ToUpper("Get"),
		"/ssh/templates",
		api.ListSSHTemplatesHandler,
	},

	Route{
		"ManageSSHTemplate",
		strings.ToUpper("Put"),
		"/ssh/template",
		api.ManageSSHTemplateHandler,
	},

	Route{
		"DeleteSSHTemplate",
		strings.ToUpper("Delete"),
		"/ssh/template/{templateName}",
		api.DeleteSSHTemplateHandler,
	},

	Route{
		"CreateSSHCertificate",
		strings.ToUpper("Post"),
		"/ssh/certificate/create",
		api.CreateSSHCertificateHandler,
	},

	Route{
		"Health",
		strings.ToUpper("Get"),
		"/health",
		GetHealthHandler,
	},
}
