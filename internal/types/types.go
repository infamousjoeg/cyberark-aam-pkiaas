package types

import "time"

// CreateCertReq ---------------------------------------------------------------
// Structure that represents an actual certificate request corresponding to the
// JSON body from the '/certificate/create' endpoint
type CreateCertReq struct {
	TemplateName string   `json:"templateName"`
	CommonName   string   `json:"commonName"`
	TTL          int64    `json:"ttl"`
	AltNames     []string `json:"altNames,omitempty"`
	Format       string   `json:"format,omitempty"`
}

// Template --------------------------------------------------------------------
// Structure that represents a certificate request template corresponding to the
// JSON body from the '/template/create' and '/template/manage' endpoints
type Template struct {
	TemplateName       string        `json:"templateName"`
	KeyAlgo            string        `json:"keyAlgo"`
	KeyBits            string        `json:"keyBits"`
	MaxTTL             int64         `json:"maxTTL"`
	Subject            SubjectFields `json:"subject"`
	KeyUsages          []string      `json:"keyUsages,omitempty"`
	ExtKeyUsages       []string      `json:"extKeyUsages,omitempty"`
	ValidateCNHostname bool          `json:"validateCNHostname,omitempty"`
	PermitLocalhostCN  bool          `json:"permitLocalhostCN,omitempty"`
	PermitWildcardCN   bool          `json:"permitWildcardCN,omitempty"`
	PermitRootDomainCN bool          `json:"permitRootDomain,omitempty"`
	PermitSubdomainCN  bool          `json:"permitSubdomainCN,omitempty"`
	AllowedCNDomains   []string      `json:"allowedCNDomains,omitempty"`
	PermDNSDomains     []string      `json:"permDNSDomains,omitempty"`
	ExclDNSDomains     []string      `json:"exclDNSDomains,omitempty"`
	PermIPRanges       []string      `json:"permIPRanges,omitempty"`
	ExclIPRanges       []string      `json:"exclIPRanges,omitempty"`
	PermEmails         []string      `json:"permEmails,omitempty"`
	ExclEmails         []string      `json:"exclEmails,omitempty"`
	PermURIDomains     []string      `json:"permURIDomains,omitempty"`
	ExclURIDomains     []string      `json:"exclURIDomains,omitempty"`
	PolicyIdentifiers  []string      `json:"policyIdentifiers,omitempty"`
}

// CreateCertificateResponse ---------------------------------------------------
// Structure that respresents the JSON response that is returned from the '/certificate/create'
// and '/certificate/sign' endpoints
type CreateCertificateResponse struct {
	Certificate   string `json:"certificate"`
	PrivateKey    string `json:"privateKey,omitempty"`
	CACert        string `json:"caCertificate"`
	SerialNumber  string `json:"serialNumber"`
	LeaseDuration int64  `json:"leaseDuration"`
}

// CreateCertificateData ---------------------------------------------------
// Structure that correspond to all the new certificate data that is written
// to the storage backend used by endpoints '/certificate/create' and 'certificate/sign'
type CreateCertificateData struct {
	Certificate          string `json:"certificate"`
	Revoked              bool   `json:"revoked"`
	RevocationDate       string `json:"revocationDate"`
	RevocationReasonCode int    `json:"revocationReasonCode"`
	ExpirationDate       string `json:"expirationDate"`
	SerialNumber         string `json:"serialNumber"`
	InternalState        string `json:"internalState"`
}

// PEMCertificate -----------------------------------------------------------------
// Structure representing a single PEM-encoded X.509 certificate
type PEMCertificate struct {
	Certificate string `json:"certificate"`
}

// PEMCertificateBundle -----------------------------------------------------------
// Structure representing a PEM-bundle of X.509 certificates
type PEMCertificateBundle struct {
	CertBundle string `json:"certBundle"`
}

// PEMIntermediate ----------------------------------------------------------------
// Structure representing a new PEM-encoded intermediate response from the '/ca/generate'
// endpoint. The CSR property will be set unless generating a self-signed CA
type PEMIntermediate struct {
	CSR            string `json:"csr,omitempty"`
	SelfSignedCert string `json:"selfSignedCert,omitempty"`
}

// CertificateListResponse -----------------------------------------------------
// A structure that contains a JSON representation of certificate serial number strings
// returned as the response for endpoint '/certificates'
type CertificateListResponse struct {
	Certificates []string `json:"certificates"`
}

// TemplateListResponse --------------------------------------------------------
// A structure that contains a JSON representation of template names returned as
// the response for endpoint '/templates'
type TemplateListResponse struct {
	Templates []string `json:"templates"`
}

// SignRequest -----------------------------------------------------------------
// Structure that represents a certificate request corresponding to the
// JSON body from the '/certificate/sign' endpoint
type SignRequest struct {
	CSR          string `json:"csr"`
	CommonName   string `json:"commonName"`
	TemplateName string `json:"templateName"`
	TTL          int64  `json:"ttl,omitempty"`
	ReturnFormat string `json:"returnFormat,omitempty"`
}

// IntermediateRequest --------------------------------------------------------
// Structure that represents an intermediate CA certificate request corresponding to the
// JSON body from the '/ca/generate' endpoint
type IntermediateRequest struct {
	CommonName string        `json:"commonName"`
	KeyAlgo    string        `json:"keyAlgo"`
	KeyBits    string        `json:"keyBits"`
	MaxTTL     int64         `json:"maxTTL"`
	Subject    SubjectFields `json:"subject"`
	AltNames   []string      `json:"altNames,omitempty"`
	SelfSigned bool          `json:"selfSigned,omitempty"`
}

// RevokeRequest --------------------------------------------------------------
// Structure that represents a certificate revocation request corresponding to the
// JSON body from the '/certificate/revoke' endpoint
type RevokeRequest struct {
	SerialNumber string `json:"serialNumber"`
	Reason       string `json:"reason,omitempty"`
}

// SubjectFields -------------------------------------------------------------
// A breakdown of subject fields corresponding to the pkix.Name object used by
// template and certificate objects
type SubjectFields struct {
	Organization string `json:"organization,omitempty"`
	OrgUnit      string `json:"orgUnit,omitempty"`
	Country      string `json:"country,omitempty"`
	Locality     string `json:"locality,omitempty"`
	Province     string `json:"province,omitempty"`
	Address      string `json:"address,omitempty"`
	PostalCode   string `json:"postalCode,omitempty"`
}

// CABasicConstraints --------------------------------------------------------
// Data structure used for marshaling CA specific information into a CSR
type CABasicConstraints struct {
	CA                bool `json:"ca,omitempty"`
	PathLenConstraint int  `json:"pathLenConstraint,omitempty"`
}

// RevokedCertificate --------------------------------------------------------
// Structure used to read data from write data to the storage backend related to
// existing and new revoked certificates, and used in the '/certificate/revoke'
// endpoint
type RevokedCertificate struct {
	SerialNumber   string
	ReasonCode     int
	RevocationDate time.Time
}
