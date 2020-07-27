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