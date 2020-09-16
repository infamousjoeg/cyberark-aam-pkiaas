## Templates
Templates are required to issue certificates with the PKI Service. Every certificate is created from a template. After creating the templates you can grant identites (host, user, roles, etc) to generate certificates from these templates.

This is the most simplistic template that can be created:
```json
{
  "templateName": "simpleTemplate",
  "keyAlgo": "RSA",
  "keyBits": "2048",
  "maxTTL": 3600
}
```

Here is an example of a more complex template, that is enforcing rules and validates these rules at time of certificate creation.
The example below is a `complexTemplate` for shortlived certificates (TTL no longer than 60 mins) and are not stored in the backend database.
When a certificate is generated we will validate the CN and also allow localhost in the CN. The certificate cannot contain a wildercard. The certificate cannot be the root domain. The certficiate must have a subdomain as the CN.
```json
{
  "templateName": "complexTemplate",
  "keyAlgo": "RSA",
  "keyBits": "2048",
  "maxTTL": 60,
  "storeCertificate": false,
  "validateCNHostname": true,
  "permitLocalhostCN": true,
  "permitWildcardCN": false,
  "permitRootDomain": false,
  "permitSubdomainCN": true,
  "allowedCNDomains": [
    "app1.namespace.svc.cluster.local",
	"app2.namespace.svc.cluster.local",
	"app3.namespace.svc.cluster.local",
	"app4.namespace.svc.cluster.local",
	"app5.namespace.svc.cluster.local",
	"app6.namespace.svc.cluster.local"
  ]
}
```

- `templateName`: Name of the template
- `keyAlgo`: Supported key algorithms are: RSA, ECDSA or ED25519.
- `keyBits`: Is directly related to the `keyAlgo`. If the `keyBits` field is incorrect in relation with the `keyAlgo` then an error will be returned.
  - When `keyAlgo` is `RSA` then `keyBits` must be between 2048 and 8192.
  - When `keyAlgo` is `ECDSA` then `keyBits` must be p224, p256, p384 or p521.
  - When `keyAlg` is `ED25519` then `keyBits` is ignored.
- `maxTTL`: Maximuim time to live in minutes. Certificates created from this template cannot have a TTL longer than the `maxTTL`. If the client provided a TTL longer than the `maxTTL` an error WILL NOT be returned but the certificate will adhere to the `maxTTL` setting on the template.
- `subject`: ROB TODO
- `storeCertificate`: Certificates created from this template will be stored into the backend by default. If `storeCertificate` is `false` then certificates generated will not be stored in the backend. This is helpful to keep the CRL small, generating short-lived certificates and reducing load on the storage backend.
- `keyUsages`: ROB TODO: Valid key usages are: digitalSignature, keyEncipherment, dataEncipherment, contentCommitment, keyAgreement, certSign, crlSign, encipherOnly and decipherOnly
- `extKeyUsages`: ROB TODO: Valid extended key usages are: any, serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, OCSPSigning, ipsecEndSystem, ipsecTunnel, ipsecUser, msSGC, nsSGC, msCodeCom and msCodeKernel
- `validateCNHostname`: Default is `false`. ROB TODO:
- `permitLocalhostCN`: Default is `false`. If `permitLocalHostCN` is `true` then certificates generated from this template can provide `localhost` in the CN.
- `permitWildcardCN`: Default is `false`. If `permitWildcardCN` is `true` then certificates generated from this template can provide a wildcard in the CN.
- `permitRootDomain`: Default is `false`. If `permitRootDomain` is `true` then TODO ROB
- `permitSubdomainCN`: Default is `false`. If `permitSubdomainCN` is `true` then certificates generated from this template can contain a sub-domain in CN or SAN.
- `allowedCNDomains`: Default is to allow all CN domains. If `allowedCNDomains` is provided then whenever a certificate is generated for this template then the CN will be validated against the `allowedCNDomains` list. An error will be returned if the client attempts to generate a certificate with a CN that is not provided in this list.
- `permDNSDomains`: Default is to allow all SAN domains. If `permDNSDomains` is provided then when a certificate is generated from this template then the SAN will be validated against the `permDNSDomains` list. An error will be returned if the client attempts to generate a certificate with a SAN that is not provided in this list.
- `exclDNSDomains`: Default is to not exclude SAN domains. This attribute is similar to `permDNSDomains` but instead is inverse.
- `permIPRanges`: Default is to allow all ip ranges. If `permIPRanges` is provided then certificates generated from this template can contain IP ranges in the SANs. An error will be returned if the client attempts to generate a certificate with a SAN that is not provided in this list.
- `exclIPRanges`: Default is to not exclude SAN IP ranges. This attribute is similar to `permIPRanges` but instead is inverse.
- `permEmails`: Default is to allow all emails provided in SANs. An error will be returned if the client attempts to generate a certificate with a SAN containing an email that is not provided in the `permEmails` list.
- `exclEmails`: Default is to not exclude SAN emails. This attribute is similar to `permEmails` but instead is inverse.
- `permURIDomains`: Default is to allow all SAN URIs. If `permURIDomains` is provided then when a certificate is generated from this template the SANs will be validated against the provided list. An error will be returned if the client attempts to generate a certificate with a SAN URI that is not provided in the `permURIDomains` list.
- `exclURIDomains`: Default is to not exclude SAN URI domains. This attribute is similar to `permURIDomains` but is the inverse.
- `policyIdentifiers`: ROB TODO


### Groups
When a template is created then the following groups will be generated within conjur.
- `pki/templates/simpleTemplate-create-certificates`: Members of this group have the ability to generate certificates from the `simpleTemplate` template.
- `pki/templates/simpleTemplate-sign-certificates`: Members of this group have the ability to sign a CSR from the `simpleTemplate` template.
- `pki/templates/simpleTemplate-read`: Members of this group have the ability to read the configuration of the `simpleTemplate` template.
- `pki/templates/simpleTemplate-manage`: Members of this group have the ability to update the configuation of the `simpleTemplate` template.
- `pki/templates/simpleTemplate-delete`: Members of this group have the ability to delete the `simpleTemplate` template.

The following is an example policy of granting `!host app1` the ability to create certificates fromm the `simpleTemplate` template.
```yaml
# define my app1
- !host app1
# grant app1 as a member of the 'simpleTemplate-create-certificates' group
- !grant
  role: !group pki/templates/simpleTemplate-create-certificates
  member: !host app1
```


## Certificates
Applications/identities will have be able to make a request to create certificates.

Below is the most simplistic certificate creation request.
The certificate generated will have a TTL of `3600` because the `simpleTemplate` maxTTL setting is `3600`.
```json
{
  "templateName": "simpleTemplate",
  "commonName": "app1.namespace.svc.cluster.local"
}
```


Below is a more complex certificate creation request.
The template created will have a CN of `app1.namespace.svc.cluster.local` and 1 SAN of `localhost`.
The certificate generated will expire in 15 mins.
```json
{
  "templateName": "complexTemplate",
  "commonName": "app1.namespace.svc.cluster.local",
  "ttl": 15,
  "altNames": [
	  "localhost"  
  ]
}
```