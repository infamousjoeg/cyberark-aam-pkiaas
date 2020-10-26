#!/bin/bash
set -ex

source conjur_utils.sh

export CONTAINER_NAME="conjur-master"
export ADMIN_PASSWORD="CYberark11@@"
export CONJUR_ACCOUNT=conjur

docker-compose exec -T dap evoke configure master --accept-eula --hostname $CONTAINER_NAME --admin-password $ADMIN_PASSWORD $CONJUR_ACCOUNT

# wait 5 secs for service to come even though it should
sleep 5

export CONJUR_APPLIANCE_URL="https://conjur-master"
export CONJUR_AUTHN_LOGIN="admin"
export CONJUR_AUTHN_API_KEY="${ADMIN_PASSWORD}"

response=$(conjur_append_policy "root" ./policy/pki-config-policy.yml)
pki_api_key=$(echo "${response}" | jq -r ".created_roles" | jq -r '.["conjur:host:pki-service"]' | jq -r .api_key)
echo "pki-service API KEY: ${pki_api_key}"


response=$(conjur_append_policy "root" ./policy/pki-admin-policy.yml)
echo $response
api_key=$(echo "${response}" | jq -r ".created_roles" | jq -r '.["conjur:host:pki-admin"]' | jq -r .api_key)
echo "pki-admin API KEY: ${api_key}"
export CONJUR_PKI_ADMIN_API_KEY="${api_key}"

# switch to the pki-service host to perform the tests
export CONJUR_AUTHN_API_KEY="${pki_api_key}"
rm /tmp/pkiaas.env || true
echo "export CONJUR_AUTHN_API_KEY=${CONJUR_AUTHN_API_KEY}" > /tmp/pkiaas.env
echo "export CONJUR_PKI_ADMIN_API_KEY=${CONJUR_PKI_ADMIN_API_KEY}" >> /tmp/pkiaas.env