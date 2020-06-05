package types

// CreateCertReq ---------------------------------------------------------------
// Structure representing the HTTP request POSTed to the CreateCert API endpoint
type CreateCertReq struct {
	TemplateName string   `json:"templateName"`
	CommonName   string   `json:"commonName"`
	TTL          int64    `json:"ttl"`
	AltNames     []string `json:"altNames,omitempty"`
	Format       string   `json:"format,omitempty"`
}

// Template --------------------------------------------------------------------
// Structure that represents a certificate request template
type Template struct {
	TemplateName      string        `json:"templateName"`
	KeyAlgo           string        `json:"keyAlgo"`
	KeyBits           string        `json:"keyBits"`
	MaxTTL            int64         `json:"maxTTL"`
	Subject           SubjectFields `json:"subject"`
	KeyUsages         []string      `json:"keyUsages,omitempty"`
	ExtKeyUsages      []string      `json:"extKeyUsages,omitempty"`
	MaxPathLength     string        `json:"maxPathLength,omitempty"`
	PermDNSDomains    []string      `json:"permDNSDomains,omitempty"`
	ExclDNSDomains    []string      `json:"exclDNSDomains,omitempty"`
	PermIPRanges      []string      `json:"permIPRanges,omitempty"`
	ExclIPRanges      []string      `json:"exclIPRanges,omitempty"`
	PermEmails        []string      `json:"permEmails,omitempty"`
	ExclEmails        []string      `json:"exclEmails,omitempty"`
	PermURIDomains    []string      `json:"permURIDomains,omitempty"`
	ExclURIDomains    []string      `json:"exclURIDomains,omitempty"`
	PolicyIdentifiers []string      `json:"policyIdentifiers,omitempty"`
}

// CreateCertificateResponse ---------------------------------------------------
type CreateCertificateResponse struct {
	Certificate   string `json:"certificate"`
	PrivateKey    string `json:"privateKey,omitempty"`
	CACert        string `json:"caCertificate"`
	SerialNumber  string `json:"serialNumber"`
	LeaseDuration int64  `json:"leaseDuration"`
}

// CreateCertificateInDap ---------------------------------------------------
type CreateCertificateInDap struct {
	Certificate    string `json:"certificate"`
	Revoked        bool   `json:"revoked"`
	ExpirationDate string `json:"expirationDate"`
	SerialNumber   string `json:"serialNumber"`
}

// PEMCertificate -----------------------------------------------------------------
type PEMCertificate struct {
	Certificate string `json:"certificate"`
}

// PEMCertificateBundle -----------------------------------------------------------
type PEMCertificateBundle struct {
	CertBundle string `json:"certBundle"`
}

// PEMCSR -------------------------------------------------------------------------
type PEMCSR struct {
	CSR string `json:"csr"`
}

// CertificateListResponse -----------------------------------------------------
type CertificateListResponse struct {
	Certificates []string `json:"certificates"`
}

// TemplateListResponse --------------------------------------------------------
type TemplateListResponse struct {
	Templates []string `json:"templates"`
}

// SignRequest -----------------------------------------------------------------
type SignRequest struct {
	CSR          string `json:"csr"`
	CommonName   string `json:"commonName"`
	TemplateName string `json:"templateName"`
	TTL          int64  `json:"ttl,omitempty"`
	ReturnFormat string `json:"returnFormat,omitempty"`
}

// IntermediateRequest --------------------------------------------------------
type IntermediateRequest struct {
	CommonName string        `json:"commonName"`
	KeyAlgo    string        `json:"keyAlgo"`
	KeyBits    string        `json:"keyBits"`
	MaxTTL     int64         `json:"maxTTL"`
	Subject    SubjectFields `json:"subject"`
	AltNames   []string      `json:"altNames,omitempty"`
}

// RevokeRequest --------------------------------------------------------------
type RevokeRequest struct {
	SerialNumber string `json:"serialNumber"`
	Reason       string `json:"reason,omitempty"`
}

// SubjectFields -------------------------------------------------------------
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
type CABasicConstraints struct {
	CA                bool `json:"ca,omitempty"`
	PathLenConstraint int  `json:"pathLenConstraint,omitempty"`
}
