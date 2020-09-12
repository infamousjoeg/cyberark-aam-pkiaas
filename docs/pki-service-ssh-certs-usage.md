# SSH Certificate Usage Guide

All SSH Certificates need to be generated from a template. Meaning a SSH certificate template will need to be generated before users or hosts can generate SSH certificates.

So lets create our first SSH certificate template so we can start generating SSH certificates in a programmatic manner.

## Creating a SSH Certificate Template
### Permissions
The following permissions are required to create SSH certificate templates via the PKI service:
- authenticate
- create-ssh-templates

### REST API
For more information on what can be sent in the body see the [API Documentation](https://app.swaggerhub.com/apis-docs/CyberArk_AAM_SME/PKIaaS)
```bash
data='{
  "templateName": "firstTemplate",
  "certType": "User"
}'
curl --fail -H "Content-Type: application/json" \
  -H "$session_token" \
  --data "$data" \
  "https://pki.cyberark.local/ssh/template"
```

## Creating an SSH Certificate
### Permissions
The following permissions are required to create SSH Certificates:
- authenticate
- create-ssh-certificate-from-firstTemplate

### REST API
First you must generate a SSH key from the client.
```bash
sshkey-gen -t rsa
```
Then send the public key generated to the SSH certificate service.


For more information on what can be sent in the body see the [API Documentation](https://app.swaggerhub.com/apis-docs/CyberArk_AAM_SME/PKIaaS)

```bash
data='{
  "templateName": "firstTemplate",
  "publicKey": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC/rc1ld4uHSUzVNHYWqpE1pTmzr5vUA81QFLOs3cllrWDnJ114cGeN1TWJ/7aafCqgU2QxnTz+XpRiBRXPhOkFfbTaUy3UzqHqMV6fwrJuxBy38rCtp9qmiwoJ0uDp+uydV1R+O18a0fJMKREmUGxmti7CuEJ1U8F36t8ZGXCnNjJQyrS/9ewlKzPhK5TAwOrpeGfNRjYI4aB87dX5DLknRcuUoiQ20auCLwfyKaht6EUl/WkhLhV/NAazRu4MXYQ3xM/CK+rJ8pDW/IVb9vsHGQk9arMbHK1VU6ovpXVorUbo1o/JDUBaSadJ2f0sDqEx5a8nLgsCCyFp1G11LfUR root"
}'
curl --fail -H "$session_token" \
  -H "Content-Type: application/json" \
  --data "$data" \
  "https://pki.cyberark.local/ssh/certificate"
```