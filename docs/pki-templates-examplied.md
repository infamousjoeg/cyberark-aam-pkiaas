# PKI
## Templates
Templates are required to issue certificates with the PKI Service. Every certificate is created from a template. So one of the first things to do (after setting up the intermediate certificate) is to create templates. After creating the templates you can grant identites (host, user, etc) to generate certificates from these templates.

Below we will go over the bare miniumum PKI Template. After that we will dive into more advanced PKI Templates that can enforce more rules/contraints.


This is the most simplistic template that can be created:
```json
{
  "templateName": "testTemplate",
  "keyAlgo": "RSA",
  "keyBits": "2048",
  "maxTTL": 3600
}
```

Here is an example of a more complex template:
```json
{
  "templateName": "complexTemplate",
  "keyAlgo": "RSA",
  "keyBits": "2048",
  "maxTTL": 3600,
  "subject": {},
  "storeCertificate": true,
  "keyUsages": [
    "string"
  ],
  "extKeyUsages": [
    "string"
  ],
  "validateCNHostname": true,
  "permitLocalhostCN": true,
  "permitWildcardCN": true,
  "permitRootDomain": true,
  "permitSubdomainCN": true,
  "allowedCNDomains": [
    "string"
  ],
  "permDNSDomains": [
    "string"
  ],
  "exclDNSDomains": [
    "string"
  ],
  "permIPRanges": [
    "string"
  ],
  "exclIPRanges": [
    "string"
  ],
  "permEmails": [
    "string"
  ],
  "exclEmails": [
    "string"
  ],
  "permURIDomains": [
    "string"
  ],
  "exclURIDomains": [
    "string"
  ],
  "policyIdentifiers": [
    "string"
  ]
}

```


- `templateName`: Name of the template
- `keyAlgo`: Supported key alogrithms are: RSA, ECDSA or ED25519.
- `keyBits`: Is directly related to the `keyAlgo`. If the `keyBits` field is incorrect in relation with the `keyAlgo` then an error will be returned.
  - When `keyAlgo` is `RSA` then `keyBits` must be between 2048 and 8192.
  - When `keyAlgo` is `ECDSA` then `keyBits` must be p224, p256, p384 or p521.
  - When `keyAlg` is `ED25519` then `keyBits` is ignored.
- `maxTTL`: Maximuim time to live in minutes. Certificates created from this template cannot have a TTL longer than the `maxTTL`
- `subject`: ROB TODO
- `storeCertificate`: Certificates created from this template will be stored into the backend by default. If `storeCertificate` is `false` then certificates generated will not be stored in the backend. This is helpful to keep the CRL small, generating short-lived certificates and reducing load on the storage backend.
- `keyUsages`: ROB TODO: Valid key usages are: digitalSignature, keyEncipherment, dataEncipherment, contentCommitment, keyAgreement, certSign, crlSign, encipherOnly and decipherOnly
- `extKeyUsages`: ROB TODO: Valid extened key usages are: any, serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, OCSPSigning, ipsecEndSystem, ipsecTunnel, ipsecUser, msSGC, nsSGC, msCodeCom and msCodeKernel
- `validateCNHostname`: Default is `false`. ROB TODO:
- `permitLocalhostCN`: Default is `false`. If `permitLocalHostCN` is `true` then certificates generated from this template can provide `localhost` in the common name or subject alternative name (SAN).
- `permitWildcardCN`: Default is `false`. If `permitWildcardCN` is `true` then certificates generated from this template can provide a wildcard in the common name or subject alternative name (SAN).
- `permitRootDomain`: Default is `false`. If `permitRootDomain` is `true` then TODO ROB
- `permitSubdomainCN`: Default is `false`. If `permitSubdomainCN` is `true` then certificates generated from this template can contain a sub-domain in CN or SAN.
- `allowedCNDomains`: Default is to allow all CN domains. If `allowedCNDomains` is provided then whenever a certificate is generated for this template then the common name will be validated against the `allowedCNDomains` list. An error will be returned if the client attempts to generate a certificate with a CN that is not provided in this list.
- `permDNSDomains`: Default is to allow all SAN domains. If `permDNSDomains` is provided then when a certificate is generated from this template then the SAN will be validated against the `permDNSDomains` list. An error will be returned if the client attempts to generate a certificate with a SAN that is not provided in this list.
- `exclDNSDomains`: Default is to not exclude SAN domains. This attribute is similar to `permDNSDomains` but instead is inverse.
- `permIPRanges`: Default is to allow all ip ranges. If `permIPRanges` is provided then certificates generated from this template can contain IP ranges in the SAN. An error will be returned if the client attempts to generate a certificate with a SAN that is not provided in this list.
- `exclIPRanges`: Default is to not exclude SAN IP ranges, This attribute is similar to `permIPRanges` but instead is inverse.
- `permEmails`: Default is to allow all emails provided in SANs. An error will be returned if the client attempts to generate a certificate with a SAN containing an email that is not provided in the `permEmails` list.
- `exclEmails`: Default is to not exclude SAN emails. This attribute is similar to `permEmails` but instead is inverse.
- `permURIDomains`: Default is not allow all SAN URIs. If `permURIDomains` if provided then when a certificate is generated from this template the SANs will be validated against the procvided list. An error will be returned if the client attempts to generate a certificate with a SAN URI that is not provided in the `permURIDomains` list.
- `exclURIDomains`: Default is to not exclude SAN URI domains. This attribute is similar to `permURIDomains` but is the inverse.
- `policyIdentifiers`: ROB TODO
