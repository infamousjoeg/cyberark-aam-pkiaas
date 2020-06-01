package types

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

// Template --------------------------------------------------------------------
// Structure that represents a certificate request template
type Template struct {
	TemplateName      string        `json:"templateName"`
	KeyAlgo           string        `json:"keyAlgo"`
	KeyBits           string        `json:"keyBits"`
	MaxTTL            int64         `json:"maxTTL"`
	Subject           SubjectFields `json:"subject"`
	KeyUsages         []string      `json:"keyUsages"`
	ExtKeyUsages      []string      `json:"extKeyUsages"`
	MaxPathLength     string        `json:"maxPathLength"`
	PermDNSDomains    []string      `json:"permDNSDomains"`
	ExclDNSDomains    []string      `json:"exclDNSDomains"`
	PermIPRanges      []string      `json:"permIPRanges"`
	ExclIPRanges      []string      `json:"exclIPRanges"`
	PermEmails        []string      `json:"permEmails"`
	ExclEmails        []string      `json:"exclEmails"`
	PermURIDomains    []string      `json:"permURIDomains"`
	ExclURIDomains    []string      `json:"exclURIDomains"`
	PolicyIdentifiers []string      `json:"policyIdentifiers"`
}

// CreateCertificateResponse ---------------------------------------------------
type CreateCertificateResponse struct {
	Certificate   string `json:"certificate"`
	PrivateKey    string `json:"privateKey"`
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

// SignRequest -----------------------------------------------------------------
type SignRequest struct {
	CSR          string `json:"csr"`
	CommonName   string `json:"commonName"`
	TemplateName string `json:"templateName"`
	TTL          int64  `json:"ttl"`
	ReturnFormat string `json:"returnFormat"`
}

// IntermediateRequest --------------------------------------------------------
type IntermediateRequest struct {
	CommonName string        `json:"commonName"`
	KeyAlgo    string        `json:"keyAlgo"`
	KeyBits    string        `json:"keyBits"`
	MaxTTL     int64         `json:"maxTTL"`
	Subject    SubjectFields `json:"subject"`
	AltNames   []string      `json:"altNames"`
}

// RevokeRequest --------------------------------------------------------------
type RevokeRequest struct {
	SerialNumber string `json:"serialNumber"`
	Reason       string `json:"reason"`
}

// SubjectFields -------------------------------------------------------------
type SubjectFields struct {
	Organization string `json:"organization"`
	OrgUnit      string `json:"orgUnit"`
	Country      string `json:"country"`
	Locality     string `json:"locality"`
	Province     string `json:"province"`
	Address      string `json:"address"`
	PostalCode   string `json:"postalCode"`
}

// CABasicConstraints --------------------------------------------------------
type CABasicConstraints struct {
	CA                bool `json:"ca,omitempty"`
	PathLenConstraint int  `json:"pathLenConstraint,omitempty"`
}
