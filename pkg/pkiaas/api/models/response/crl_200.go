package api

// CRL200 //
type CRL200 struct {
	Count int32 `json:"count,omitempty"`

	Records []CRLRecords `json:"records,omitempty"`
}
