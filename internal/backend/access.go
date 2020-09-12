package backend

// Access ------------------
// Interface that defines all the methods that will be
// required to develop a backend system's Access Control
// objects
type Access interface {
	Authenticate(accessToken string) error
	ListTemplates(accessToken string) error
	ReadTemplate(accessToken string, templateName string) error
	DeleteTemplate(accessToken string, templateName string) error
	ManageTemplate(accessToken string, templateName string) error
	CreateTemplate(accessToken string) error
	ListSSHTemplates(accessToken string) error
	CreateSSHTemplate(accessToken string) error
	ReadSSHTemplate(accessToken string, templateName string) error
	DeleteSSHTemplate(accessToken string, templateName string) error
	ManageSSHTemplate(accessToken string, templateName string) error
	CreateSSHCertificate(accessToken string, templateName string) error
	Purge(accessToken string) error
	CRLPurge(accessToken string) error
	CreateCertificate(accessToken string, templateName string) error
	RevokeCertificate(accessToken string, serialNumber string) error
	SignCertificate(accessToken string, templateName string) error
	GenerateIntermediateCSR(accessToken string) error
	SetIntermediateCertificate(accessToken string) error
	SetCAChain(accessToken string) error
}
