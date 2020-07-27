# Conjur PKI Service Implementation Guide

_Last Updated: 2020-07-27_

## Pre-Requisite

* PKI service is up and running

## Configuration

We will have to create a `pki-admin` host. This host will have the ability to execute all Conjur PKI Service endpoints. This host is highly sensitive. Make sure to manage this host within [CyberArk PAS](https://cyberark.com) or delete this user after initial configuration.

Load the following policy to generate a `pki-admin` host and give this host admin privileges on the pki service:

```yaml
- !host pki-admin
- !grant
  role: !group pki/admin
  member: !host pki-admin
```

Load the above policy on the `root` policy branch.

You should receive a response similar to:

```json
{
  "created_roles": {
    "cyberarkdemo:host:pki-admin": {
      "id": "cyberarkdemo:host:pki-admin",
      "api_key": "1bzwdwq2mpjpct3qtth2n2wjkh4q28qrx411rcjx9cakp5h16966jw"
    }
  },
  "version": 3
}
```

An `api_key` will be returned. You can onboard this host and `api_key` into Cyberark PAS for secure storage and management.

### Generating Intermediate Certificate

You can now authenticate to Conjur using the returned `api_key` and generate a CA certificate.

```bash
# Get the conjur access token and create header
access_token=$(curl https://<conjur instance>/authn/<account>/host%2Fpki-admin/authenticate --data "1bzwdwq2mpjpct3qtth2n2wjkh4q28qrx411rcjx9cakp5h16966jw" | base64)
header="Authorization: Token token=\"$access_token\""

# This should return with 'OK'
curl https://<conjur pki service>/health

# Now lets generate a self-signed certificate for the Conjur PKI Service. SELF SIGNED CERTIFICATE SHOULD ONLY BE USED FOR POCs.
curl -H "$header" --data '{"commonName": "my-pki-service.local", "keyAlgo": "RSA", "keySize": "2048"}' https://<conjur pki service>/ca/generate/selfsigned 
```

The CA certificate and signing key have been generated and are stored within the Conjur PKI Service.

### Creating a Template

Now, we must create a Template within the Conjur PKI Service. A Template is required to create any certificate. Corresponding groups are created within Conjur when a Template is created. To generate a Template execute the following command:

```bash
# This is a small JSON object representing a Template
# More JSON attributed can be found in the Conjur PKI Service REST API documentation
data='
{
  "templateName": "testTemplate",
  "keyAlgo": "RSA",
  "keyBits": "2048",
  "maxTTL": 3600
}
'
curl -H "$header" --data "$data" https://<conjur pki service>/template/create 
```

A `200` response code will be returned if the Template was created successfully.

At this point, we have generated the CA certificate and have created a Template to create certificates from.

### Creating a Certificate

To create a certificate from the Conjur PKI Service execute the following bash commands:

```bash
data=`
{
  "templateName": "testTemplate",
  "commonName": "some.app.certificate.company.local"
}
`
curl -H "$header" --data "$data" https://<conjur pki service>/certificate/create 
```

The returned response should look like the following:

```json
{
  "certificate": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----\n",
  "privateKey": "-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----\n",
  "caCertificate": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----\n",
  "serialNumber": "10:61:47:34:30:46:03:b1:51:db:df:c3:50:60:85:78:cf"
}
```

The application may now use the certificate, private key or CA certificate to perform its duty.

## Application Configuration

In the steps above, we went through the entire process of generating an intermediate CA, creating a template, and generating a certificate from the template. However, in production systems, we want to make sure our applications have least privilege and can only create certificates from explicit templates.

### Create Certificate

Load the policy below to grant `app1` the ability to create certificates from `testTemplate`.

```yaml
- !host app1
- !grant
  role: !group pki/templates/testTemplate-create-certificates
  member: !host app1
```

### Sign CSR

If `app1` generates its own CSR then the following policy will need to be loaded to allow the application to sign this CSR from `testTemplate`:

```yaml
- !host app1
- !grant
  role: !group pki/templates/testTemplate-sign-certificates
  member: !host app1
```

