# CyberArk PKI Service <!-- omit in toc -->

A service written in Golang providing just-in-time generation of X.509 certificates based on a trusted Intermediate CA following all RFC guidelines and ASN.1 compliance.

[![](https://img.shields.io/github/v/release/infamousjoeg/cyberark-aam-pkiaas?include_prereleases)](https://github.com/infamousjoeg/cyberark-aam-pkiaas/releases/latest) ![PKIaaS Tests](https://github.com/infamousjoeg/cyberark-aam-pkiaas/workflows/PKIaaS%20Tests/badge.svg) [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=infamousjoeg_cyberark-aam-pkiaas&metric=alert_status&token=17e046f3fe9c8c663345609fe591b5c06e214e2c)](https://sonarcloud.io/dashboard?id=infamousjoeg_cyberark-aam-pkiaas) [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=infamousjoeg_cyberark-aam-pkiaas&metric=security_rating&token=17e046f3fe9c8c663345609fe591b5c06e214e2c)](https://sonarcloud.io/dashboard?id=infamousjoeg_cyberark-aam-pkiaas)

## Table of Contents <!-- omit in toc -->

- [Requirements](#requirements)
- [Configuration & Deployment](#configuration--deployment)
- [Usage](#usage)
  - [Generating Intermediate Certificate](#generating-intermediate-certificate)
  - [Creating a Template](#creating-a-template)
  - [Creating a Certificate](#creating-a-certificate)
  - [API Documentation](#api-documentation)
- [Maintainers](#maintainers)
- [Contributing](#contributing)
- [License](#license)

## Requirements

* A supported backend
  * [CyberArk Conjur](https://conjur.org)

## Configuration & Deployment

1. Follow the instructions in [PKI Service Implementation Guide](docs/pki-service-implementation.md) to prepare the Conjur backend to accept the PKI service connection.
2. Follow the instructions in [PKI Service Installation Guide](docs/pki-service-installation.md) to deploy the service into [Docker](https://docker.com) standalone or [Kubernetes](https://kubernetes.io).
3. Review the [Conjur Policy Backend Reference Guide](docs/conjur-policy-backend.md) to begin learning the authorization privileges used.

## Usage

As of Alpha (current), the PKI service listens over port `8080`. This port may be changed by providing the environment variable `PORT` with a new value.

For more detailed documentation, please read [PKI Service Usage Guide](docs/pki-service-usage.md).

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

### API Documentation

For more information regarding the PKI API provided, please see the documentation on SwaggerHub at: [https://app.swaggerhub.com/apis-docs/CyberArk_AAM_SME/PKIaaS]()

## Maintainers

[@infamousjoeg](https://github.com/infamousjoeg)
[@rcobbins](https://github.com/rcobbins)
[@AndrewCopeland](https://github.com/AndrewCopeland)
[@daswak](https://github.com/daswak)

[List of Contributors](https://github.com/infamousjoeg/cyberark-aam-pkiaas/graphs/contributors)

## Contributing

We welcome contributions of all kinds to this repository. For instructions on how to get started and descriptions of our development workflows, please see our [contributing guide](CONTRIBUTING.md).

## License

[Apache License 2.0](LICENSE)