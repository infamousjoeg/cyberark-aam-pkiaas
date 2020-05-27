package api

// CertificateCreate201 //
type CertificateCreate201 struct {
	CommonName string `json:"commonName,omitempty"`

	TemplateName string `json:"templateName,omitempty"`

	TimeToLive int32 `json:"timeToLive,omitempty"`

	ReturnFormat string `json:"returnFormat,omitempty"`
}
