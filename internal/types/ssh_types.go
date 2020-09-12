package types

// SSHTemplate -------------------
type SSHTemplate struct {
	TemplateName             string               `json:"templateName"`
	CertType                 string               `json:"certType"`
	MaxTTL                   uint64               `json:"maxTTL"`
	AllowedHosts             []string             `json:"allowedHosts,omitempty"`
	AllowedPrincipals        []string             `json:"allowedPrincipals,omitempty"`
	PermittedCriticalOptions []SSHCriticalOptions `json:"permittedCriticalOptions,omitempty"`
	PermittedExtensions      []string             `json:"permittedExtensions,omitempty"`
}

// SSHCertificate --------------------------
type SSHCertificate struct {
	Certificate string `json:"certificate"`
}

// SSHCertificateList ----------------------
type SSHCertificateList struct {
	SSHCertificates []string `json:"sshCertificates"`
}

// SSHSignRequest -----------------
type SSHSignRequest struct {
	TemplateName    string               `json:"templateName"`
	PublicKey       string               `json:"publicKey"`
	ValidPrincipals []string             `json:"users,omitempty"`
	Domains         []string             `json:"domains,omitempty"`
	TTL             uint64               `json:"ttl"`
	KeyID           string               `json:"keyId,omitempty"`
	CriticalOptions []SSHCriticalOptions `json:"criticalOptions,omitempty"`
	Extensions      []string             `json:"extensions,omitempty"`
}

// SSHSignResponse ----------------------
type SSHSignResponse struct {
	SerialNumber      string `json:"serialNumber"`
	SignedCertificate string `json:"signedCertificate"`
}

// SSHRevokeRequest ------------------
type SSHRevokeRequest struct {
	SerialNumber string `json:"serialNumber"`
}

// SSHCriticalOptions ----------------
type SSHCriticalOptions struct {
	Option string `json:"option"`
	Value  string `json:"value"`
}
