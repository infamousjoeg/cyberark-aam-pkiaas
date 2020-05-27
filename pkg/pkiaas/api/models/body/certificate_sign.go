package api

// CertificateSignBody //
// /certificate/sign/ Body data model
type CertificateSignBody struct {
	CommonName string `json:"commonName,omitempty"`

	TemplateName string `json:"templateName,omitempty"`

	EmailAddress string `json:"emailAddress,omitempty"`

	TimeToLive int32 `json:"timeToLive,omitempty"`

	ReturnFormat string `json:"returnFormat,omitempty"`
}
