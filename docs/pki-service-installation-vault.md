# Vault PKI Service Installation Guide

## Pre-Requisites

* This Installation Guide assumes you already have a running vault instance.
* The PKI Service will need access to the Vault instance.
* The PKI Service container image has been pulled and available to the docker daemon or the k8s cluster. (e.g. `docker pull docker.pkg.github.com/infamousjoeg/cyberark-aam-pkiaas/pkiaas:v0.7.3-alpha`)

## Configuration

To configure the PKI service you can run the following command to enable the `pki-service` secrets engine.
```bash
vault secrets enable -version=2 -path=pki-service kv
```

Then we must create a policy named `pki-service` that represents the application of the PKI service.
```bash
echo '
path "pki-service/data/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}' | vault policy write pki-service -
```

Then we create another policy names `pki-service-admin` that represents and admin user of the PKI service.
```bash
echo '
path "pki-service/authenticate" {
    capabilities = ["read"]
}
path "pki-service/generate-intermediate-csr" {
    capabilities = ["read"]
}
path "pki-service/set-intermediate-certificate" {
    capabilities = ["read"]
}
path "pki-service/set-ca-chain" {
    capabilities = ["read"]
}
path "pki-service/purge" {
    capabilities = ["read"]
}
path "pki-service/purge-crl" {
    capabilities = ["read"]
}
path "pki-service/templates/*" {
    capabilities = ["read"]
}
path "pki-service/certificates/*" {
    capabilities = ["read"]
}' | vault policy write pki-service-admin -
```

For simplicity sake, we will generate a token for the PKI service application and the PKI Service admin.

To generate the PKI service token perform the following command:
```bash
vault token create -policy=pki-service
```
*REMEMBER THIS TOKEN WILL BE USED WHEN DEPLOYING THE PKI SERVICE*

To generate the PKI service admin token perform the following command:
```bash
vault token create -policy=pki-service-admin
```

## Deployment

### Docker Standalone

The following is how to deploy the PKI Service within a Docker Compose file.
The environment variables that can be used are mentioned [here](https://www.vaultproject.io/docs/commands#environment-variables)

```yaml
version: "3"
services:
  pkiaas:
    image: conjur-pkiaas:latest
    environment:
	  PKI_VAULT_BACKEND: yes
	  VAULT_ADDR: https://vault.company.local
	  VAULT_TOKEN: s.wOrq5pMIOoSjIt8v3RIv2Z7N
    command: /app/pkiaas
    ports:
      - "8080:8080"
```