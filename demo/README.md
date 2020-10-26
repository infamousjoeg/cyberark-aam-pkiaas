# PKI Service Demo Environment

A quick and easy local demonstration environment for showcasing CyberArk's PKI Service and signed SSH certificates against DAP.

## Requirements

* Docker
* Docker Compose

## Usage

```shell
./deploy.sh [up/down]
```

Execute [deploy.sh]() with either the `up` or `down` argument as shown in the above example.

```shell
docker-compose exec pkiaas-tester bash
```

The `pkiaas-tester` container is where you will demonstrate from within. It is also the host server for the signed SSH certificates demonstration.

```shell
source /app/env/pkiaas.env
cd /app/demo
./demo.sh
```

| Description | Path |
|---|---|
| Certificate | `/app/cert/conjur-master.pem` |
| Environment Variables | `/app/env/pkiaas.env` |
| Demo Scripts  | `/app/demo` |