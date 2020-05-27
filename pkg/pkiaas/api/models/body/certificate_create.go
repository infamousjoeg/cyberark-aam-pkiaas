package api

// CertificateCreateBody //
// /certificate/create/ Body data model
type CertificateCreateBody struct {
	CommonName string `json:"commonName,omitempty"`

	TemplateName string `json:"templateName,omitempty"`

	TimeToLive int32 `json:"timeToLive,omitempty"`

	ReturnFormat string `json:"returnFormat,omitempty"`
}
