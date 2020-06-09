# cyberark-aam-pkiaas
CyberArk AAM PKI-as-a-Service

![PKIaaS Tests](https://github.com/infamousjoeg/cyberark-aam-pkiaas/workflows/PKIaaS%20Tests/badge.svg)

## Development

Run by building from source (default port 8080):

```shell
git clone https://github.com/infamousjoeg/cyberark-aam-pkiaas
cd pkg/pkiaas
go build .
./pkiaas
```

Run by building from source (custom port 3000):

```shell
git clone https://github.com/infamousjoeg/cyberark-aam-pkiaas
cd pkg/pkiaas
go build .
export PORT=3000
./pkiaas
```

## Testing

### Pre-Requisite

* [HashiCorp Vagrant](https://vagrantup.com)

```shell
git clone https://github.com/infamousjoeg/cyberark-aam-pkiaas
cd tests
vagrant up
```