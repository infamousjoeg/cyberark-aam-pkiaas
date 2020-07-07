# Development Environment

A quick and easy local development environment for testing CyberArk's PKIaaS against DAP.

## Requirements

* Docker
* Docker Compose

## Setup

Use Docker Compose to re-build the pkiaas container and come up daemonized.

`docker-compose up --build -d`

The `dev_configurer_1` container takes care of initial configuration of the `conjur-master` as well as policy loading.  It is advised to not continue until `docker ps | grep configurer` no longer echoes a value.  This means configuration has completed.

If you'd like to Compose and wait for `dev_configurer_1` to complete configuration before continuing, you may use:

`docker-compose up --build -d && until [[ -z $(docker ps | grep configurer) ]]; do sleep 1; done`

## Usage

The `pkiaas-tester` container is where you will test from within.

`docker-compose exec pkiaas-tester bash`

| Description | Path |
|---|---|
| Certificate | `/app/cert/conjur-master.pem` |
| Environment Variables | `/app/env/pkiaas.env` |
| Dev Scripts  | `/app/dev` |

```bash
source /app/env/pkiaas.env
cd /app/dev
./setup-self-signed.sh
```

## Teardown

Use Docker Compose to remove orphans (configurer) and all volumes (`-v`).

`docker-compose down --remove-orphans -v`