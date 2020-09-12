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
    image: docker.pkg.github.com/infamousjoeg/cyberark-aam-pkiaas/pkiaas:latest
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

### Kubernetes
The following manifest is loaded to deploy the PKI service within a k8s cluster.

```yaml
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: pki-service-account
  namespace: conjur-pki-service

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pki-service
  namespace: conjur-pki-service
  labels:
    app: pki
spec:
  replicas: 1
  selector:
    matchLabels:
      role: conjur-pki-service
      app: pki-service
  template:
    metadata:
      labels:
        role: conjur-pki-service
        app: pki-service
    spec:
      serviceAccountName: pki-service-account
      shareProcessNamespace: true
      containers:
      - name: authenticator
        image: cyberark/conjur-authn-k8s-client
        imagePullPolicy: IfNotPresent
        env:
          - name: MY_POD_NAME
            valueFrom:
              fieldRef:
                fieldPath: metadata.name
          - name: MY_POD_NAMESPACE
            valueFrom:
              fieldRef:
                fieldPath: metadata.namespace
          - name: MY_POD_IP
            valueFrom:
              fieldRef:
                fieldPath: status.podIP
          - name: CONJUR_APPLIANCE_URL
            value: https://access.dap.svc.cluster.local/api
          - name: CONJUR_AUTHN_URL
            value: https://access.dap.svc.cluster.local/api/authn-k8s/k8s-follower
          - name: CONJUR_ACCOUNT
            value: cyberark
          - name: CONJUR_AUTHN_LOGIN
            value: host/pki-service
          - name: CONJUR_SSL_CERTIFICATE
            valueFrom:
              configMapKeyRef:
                name: k8s-app-ssl
                key: ssl-certificate
        volumeMounts:
          - mountPath: /run/conjur
            name: conjur-access-token
      - name: pki
        image: docker.pkg.github.com/infamousjoeg/cyberark-aam-pkiaas/pkiaas:latest
        imagePullPolicy: IfNotPresent
        env:
          - name: CONJUR_APPLIANCE_URL
            value: https://access.dap.svc.cluster.local/api
          - name: CONJUR_ACCOUNT
            value: cyberark
          - name: CONJUR_TOKEN_FILE
            value: /run/conjur/conjur-access-token
          - name: CONJUR_SSL_CERTIFICATE
            valueFrom:
              configMapKeyRef:
                name: k8s-app-ssl
                key: ssl-certificate
        volumeMounts:
          - mountPath: /run/conjur
            name: conjur-access-token
      volumes:
        - name: conjur-access-token
          emptyDir:
            medium: Memory
```
