package api

//CRLRecords //
type CRLRecords struct {
	SerialNumber int64 `json:"serialNumber"`

	RevocationDate string `json:"revocationDate"`

	Extensions []CRLExtensions `json:"extensions, omitempty"`
}
