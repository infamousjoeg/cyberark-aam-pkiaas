package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/gorilla/mux"
	"github.com/infamousjoeg/cyberark-aam-pkiaas/internal/conjur"
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

// Index route //
// Returns confirmation message on successful GET of /
func Index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Successful GET /")
}

func defaultConjurClient() (*conjurapi.Client, error) {
	config, err := conjurapi.LoadConfig()
	if err != nil {
		fmt.Printf("Failed to init config from environment variables. %s", err.Error())
		return nil, fmt.Errorf("Failed to init config from environment variables. %s", err)
	}
	client, err := conjurapi.NewClientFromEnvironment(config)
	if err != nil {
		fmt.Printf("Failed to init client from config. %s", err.Error())
		return nil, fmt.Errorf("Failed to init client from config. %s", err)
	}
	return client, err
}

func defaultTemplates() conjur.ConjurTemplates {
	return conjur.NewTemplates(testCreateTemplate(), testDeleteTemplate(), testCreateCertificate(), testDeleteCertificate())
}

func defaultConjurPki() (conjur.ConjurPki, error) {
	client, err := defaultConjurClient()
	if err != nil {
		return conjur.ConjurPki{}, err
	}
	templates := defaultTemplates()
	return conjur.NewConjurPki(client, "pki", templates), err
}

func testCreateTemplate() string {
	return `- !variable
  id: <TemplateName>
`
}

func testCreateCertificate() string {
	return `- !variable
  id: "<SerialNumber>"
`
}

func testDeleteTemplate() string {
	return `- !delete
  record: !variable <TemplateName>
`
}

func testDeleteCertificate() string {
	return `- !delete
  record: !variable <SerialNumber>
`
}

func expectedPolicy() string {
	return `- !variable
  id: TestTemplate
`
}

func init() {
	pkiclient, _ := defaultConjurPki()
	backend.Backend = pkiclient

}

var backend pki.Pki = pki.Pki{}

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
		backend.GetCAHandler,
	},

	Route{
		"GetCAChain",
		strings.ToUpper("Get"),
		"/ca/chain",
		backend.GetCAChainHandler,
	},

	Route{
		"CreateCertificate",
		strings.ToUpper("Post"),
		"/certificate/create",
		backend.CreateCertHandler,
	},

	Route{
		"GetCertificate",
		strings.ToUpper("Get"),
		"/certificate/{serialNumber}",
		backend.GetCertHandler,
	},

	Route{
		"ListCertificates",
		strings.ToUpper("Get"),
		"/certificates",
		backend.ListCertsHandler,
	},

	Route{
		"Purge",
		strings.ToUpper("Post"),
		"/purge",
		backend.PurgeHandler,
	},

	Route{
		"RevokeCertificate",
		strings.ToUpper("Post"),
		"/certificate/revoke",
		backend.RevokeCertHandler,
	},

	Route{
		"SignCertificate",
		strings.ToUpper("Post"),
		"/certificate/sign",
		backend.SignCertHandler,
	},

	Route{
		"GetCRL",
		strings.ToUpper("Get"),
		"/crl",
		backend.GetCRLHandler,
	},

	Route{
		"PurgeCRL",
		strings.ToUpper("Post"),
		"/crl/purge",
		backend.PurgeCRLHandler,
	},

	Route{
		"CreateTemplate",
		strings.ToUpper("Post"),
		"/template/create",
		backend.CreateTemplateHandler,
	},

	Route{
		"DeleteTemplate",
		strings.ToUpper("Delete"),
		"/template/delete/{templateName}",
		backend.DeleteTemplateHandler,
	},

	Route{
		"GetTemplate",
		strings.ToUpper("Get"),
		"/template/{templateName}",
		backend.GetTemplateHandler,
	},

	Route{
		"ListTemplates",
		strings.ToUpper("Get"),
		"/templates",
		backend.ListTemplatesHandler,
	},

	Route{
		"ManageTemplate",
		strings.ToUpper("Put"),
		"/template/manage",
		backend.ManageTemplateHandler,
	},

	Route{
		"GenerateIntermediateCSR",
		strings.ToUpper("Post"),
		"/ca/generate",
		backend.GenerateIntermediateCSRHandler,
	},

	Route{
		"SetIntermediateCertificate",
		strings.ToUpper("Post"),
		"/ca/set",
		backend.SetIntermediateCertHandler,
	},

	Route{
		"SetCAChain",
		strings.ToUpper("Post"),
		"/ca/chain/set",
		backend.SetCAChainHandler,
	},

	// Route{
	// 	"Health",
	// 	strings.ToUpper("Get"),
	// 	"/health",
	// 	TBD
	// },
}
