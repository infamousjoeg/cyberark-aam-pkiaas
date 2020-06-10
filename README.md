# cyberark-aam-pkiaas
CyberArk AAM PKI-as-a-Service

[![](https://img.shields.io/github/v/release/infamousjoeg/cyberark-aam-pkiaas?include_prereleases)](https://github.com/infamousjoeg/cyberark-aam-pkiaas/releases/latest) ![PKIaaS Tests](https://github.com/infamousjoeg/cyberark-aam-pkiaas/workflows/PKIaaS%20Tests/badge.svg)

## Development

Run by building from source (default port 8080):

```shell
git clone https://github.com/infamousjoeg/cyberark-aam-pkiaas
cd cyberark-aam-pkiaas
go build ./cmd/pkiaas
./pkiaas
```

Run by building from source (custom port 3000):

```shell
git clone https://github.com/infamousjoeg/cyberark-aam-pkiaas
cd cyberark-aam-pkiaas
go build ./cmd/pkiaas
export PORT=3000
./pkiaas
```

## Testing

### Pre-Requisite

* Docker CE
  * `curl -fsSL get.docker.com | sh`
* [Conjur OSS](https://conjur.org) or [CyberArk AAM Dynamic Access Provider (DAP)](https://cyberark.com)

### Usage

#### Build & Run CyberArk PKIaaS Container

```shell
docker build -t cyberark/pkiaas:test .
docker run --name pkiaas-test -d --restart always \
    -p 8080:8080 \
    -e CONJUR_AUTHN_LOGIN="host/pki-service" \
    -e CONJUR_AUTHN_API_KEY=$API_KEY \
    -e CONJUR_APPLIANCE_URL="http://localhost:${PORT}/" \
    -e CONJUR_ACCOUNT="quick-start" \
    -e CONJUR_CERT_FILE=$CERT_FILE
```