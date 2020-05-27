package api

// CertificateSign200 //
type CertificateSign200 struct {
	CommonName string `json:"commonName,omitempty"`

	Csr string `json:"csr,omitempty"`

	TemplateName string `json:"templateName,omitempty"`

	TimeToLive int32 `json:"timeToLive,omitempty"`

	ReturnFormat string `json:"returnFormat,omitempty"`
}
