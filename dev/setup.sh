#!/bin/bash

source conjur_utils.sh

export CONTAINER_NAME="conjur-master"
export ADMIN_PASSWORD="CYberark11@@"
export IMAGE_NAME="captainfluffytoes/csme:latest"
export CONJUR_ACCOUNT=conjur

docker rm -f $CONTAINER_NAME
docker container run -d --name $CONTAINER_NAME --network conjur --security-opt=seccomp:unconfined -p 443:443 -p 5432:5432 -p 1999:1999 $IMAGE_NAME
docker exec $CONTAINER_NAME evoke configure master --accept-eula --hostname $CONTAINER_NAME --admin-password $ADMIN_PASSWORD $CONJUR_ACCOUNT

# wait 5 secs for service to come even though it should
sleep 5

# the environment variables
ip_address=$(docker inspect conjur-master | jq .[0].NetworkSettings.Networks.conjur.IPAddress | tr -d \")
echo "$ip_address    conjur-master" >> /etc/hosts
export CONJUR_APPLIANCE_URL=https://conjur-master
export CONJUR_AUTHN_LOGIN=admin
export CONJUR_AUTHN_API_KEY="${ADMIN_PASSWORD}"
export CONJUR_CERT_FILE="$(pwd)/conjur.pem"

openssl s_client -showcerts -connect $CONTAINER_NAME:443 < /dev/null 2> /dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > $CONJUR_CERT_FILE

response=$(conjur_append_policy "root" ./pki-config-policy.yml)
pki_api_key=$(echo "${response}" | jq -r ".created_roles" | jq -r '.["conjur:host:pki-service"]' | jq -r .api_key)
echo "pki-service API KEY: ${pki_api_key}"


response=$(conjur_append_policy "root" ./pki-admin-policy.yml)
echo $response
api_key=$(echo "${response}" | jq -r ".created_roles" | jq -r '.["conjur:host:pki-admin"]' | jq -r .api_key)
echo "pki-admin API KEY: ${api_key}"
export CONJUR_PKI_ADMIN_API_KEY="${api_key}"

# switch to the pki-service host to perform the tests
export CONJUR_AUTHN_LOGIN="host/pki-service"
export CONJUR_AUTHN_API_KEY="${pki_api_key}"

