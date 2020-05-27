package api

// TemplateCreateBody //
type TemplateCreateBody struct {
	TemplateName string `json:"templateName"`

	KeyAlgorithm string `json:"keyAlgorithm"`

	KeyBits string `json:"keyBits"`

	TimeToLive int32 `json:"timeToLive"`

	Organization string `json:"organization"`

	OrganizationalUnit string `json:"organizationalUnit,omitempty"`

	Country string `json:"country"`

	Locality string `json:"locality"`

	Province string `json:"province,omitempty"`

	StreetAddress string `json:"streetAddress,omitempty"`

	PostalCode int32 `json:"postalCode,omitempty"`

	AltNames []string `json:"altNames,omitempty"`

	KeyUsage []string `json:"keyUsage"`

	MaxPathLength int32 `json:"maxPathLength,omitempty"`

	PermittedDNS []string `json:"permittedDNS,omitempty"`

	ExcludedDNS []string `json:"excludedDNS,omitempty"`

	PermittedIP []string `json:"permittedIP,omitempty"`

	ExcludedIP []string `json:"excludedIP,omitempty"`

	PermittedEmail []string `json:"permittedEmail,omitempty"`

	ExcludedEmail []string `json:"excludedEmail,omitempty"`

	PermittedURL []string `json:"permittedURL,omitempty"`

	ExcludedURL []string `json:"excludedURL,omitempty"`

	PolicyIdentifiers []string `json:"policyIdentifiers"`
}
