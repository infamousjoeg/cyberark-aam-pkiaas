package types

import (
	"math/big"
)

// CreateCertReq ---------------------------------------------------------------
// Structure representing the HTTP request POSTed to the CreateCert API endpoint
type CreateCertReq struct {
	TemplateName string   `json:"templateName"`
	CommonName   string   `json:"commonName"`
	EmailAddress string   `json:"emailAddress"`
	AltNames     []string `json:"altNames"`
	TTL          int64    `json:"ttl"`
	Format       string   `json:"format"`
}

// Template -------------------------------------------------------------------
// Structure that represents a certificate request template
type Template struct {
	TemplateName      string   `json:"templateName"`
	KeyAlgo           string   `json:"keyAlgo"`
	KeyBits           string   `json:"keyBits"`
	MaxTTL            int64    `json:"maxTTL"`
	Organization      string   `json:"organization"`
	OrgUnit           string   `json:"orgUnit"`
	Country           string   `json:"country"`
	Locality          string   `json:"locality"`
	Province          string   `json:"province"`
	Address           string   `json:"address"`
	PostalCode        string   `json:"postalCode"`
	KeyUsages         []string `json:"keyUsages"`
	ExtKeyUsages      []string `json:"extKeyUsages"`
	MaxPathLength     string   `json:"maxPathLength"`
	PermDNSDomains    []string `json:"permDNSDomains"`
	ExclDNSDomains    []string `json:"exclDNSDomains"`
	PermIPRanges      []string
	ExclIPRanges      []string
	PermittedEmails   []string
	ExclEmails        []string
	PermURIDomains    []string
	ExclURIDomains    []string
	PolicyIdentifiers []string //
}

// CertificateResponse -----------------------------------------
type CertificateResponse struct {
	Certificate   string   `json:"certificate"`
	PrivateKey    string   `json:"privateKey"`
	CACert        string   `json:"caCertificate"`
	SerialNumber  *big.Int `json:"serialNumber"`
	LeaseDuration int64    `json:"leaseDuration"`
}

// SignRequest ------------------------------------------------
type SignRequest struct {
	CSR          string
	commonName   string
	templateName string
	TTL          int64
	returnFormat string
}
