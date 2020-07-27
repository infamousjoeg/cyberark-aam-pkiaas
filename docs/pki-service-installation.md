# Conjur PKI Service Installation Guide

_Last Updated: 2020-07-27_

## Pre-Requisites

* This Installation Guide assumes you already have a running [Conjur](https://conjur.org) instance. 
* The Conjur PKI Service will need access to the Conjur Master cluster.
* The Conjur PKI Service container image has been pulled and available to the docker daemon or the k8s cluster. (e.g. `docker pull docker.pkg.github.com/infamousjoeg/cyberark-aam-pkiaas/pkiaas:v0.7.3-alpha`)

## Configuration

### Docker Standalone

To configure the PKI service you must load the following policy in the `root` policy branch:

```yaml
- !host pki-service
- !policy
  id: pki
  owner: !host pki-service
  body:
    - !group admin
```

When deploying the Conjur PKI Service in standalone Docker, remember to keep the `api_key` of the `!host pki-service` in a secure location since this will be needed when deploying the PKI Service container.

### Kubernetes

When deploying the Conjur PKI Service in Kubernetes, the `api_key` can be ignored. However, remember to permit the `!host pki-service` to a specific `authn-k8s` service ID. For example, if the service ID is `prod` the following policy would need to be loaded to configure the Conjur PKI Service:

```yaml
- !host 
  id: pki-service
  annotations:
    authn-k8s/namespace: conjur-pki-service
    authn-k8s/service-account: pki-service-account

- !grant
  role: !group conjur/authn-k8s/prod/apps
  member: !host pki-service

- !policy
  id: pki
  owner: !host pki-service
  body:
    - !group admin
```

## Deployment

### Docker Standalone

The following is how to deploy the Conjur PKI Service within a Docker Compose file.

The environment variables that can be used are mentioned here: [https://github.com/cyberark/summon-conjur#configuration]()

```yaml
version: "3"
services:
  pkiaas:
    image: conjur-pkiaas:latest
    environment:
      CONJUR_AUTHN_LOGIN: "host/andrews-pki-service"
      CONJUR_ACCOUNT: "cyberarkdemo"
      CONJUR_APPLIANCE_URL: "https://dap.company.local"
      CONJUR_AUTHN_API_KEY: "30dd3nfpzgqzmp370060m2tknghq1vke9ccwcw36"
      CONJUR_SSL_CERTIFICATE: |-
        -----BEGIN CERTIFICATE-----
        MIIFyDCCBLCgAwIBAgIQBTvvwR82sn7/XwgZD7NBBDANBgkqhkiG9w0BAQsFADCB
        jzELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
        ....
        G9w84FoVxp7Z8VlIMCFlA2zs6SFz7JsDoeA3raAVGI/6ugLOpyypEBMs1OUIJqsi
        l2D4kF501KKaU73yqWjgom7C12yxow+ev+to51byrvLjKzg6CYG1a4XXvi3tPxq3
        smPi9WIsgtRqAEFQ8TmDn5XpNpaYbg==
        -----END CERTIFICATE-----
    command: /app/pkiaas
    ports:
      - "8080:8080"
```