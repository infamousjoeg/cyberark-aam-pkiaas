#!/bin/bash
set -e
export CONJUR_APPLIANCE_URL=https://conjur-master
export CONJUR_AUTHN_LOGIN="host/pki-admin"
export CONJUR_CERT_FILE="$(pwd)/conjur.pem"
export CONJUR_ACCOUNT="conjur"
export CONJUR_AUTHN_API_KEY="3y455av3mxyns31kqxf692eyaw7212awnyf3z8syre3yz195w3afq2pe"

source conjur_utils.sh
session_token=$(conjur_authenticate)
export session_token="$session_token"


# revoke specific certificate
data=$(cat <<-END
{
  "serialNumber": "10:28:51:3a:20:26:23:05:f9:8a:40:56:bc:ed:9f:3a:4b",
  "reason": "keyCompromise"
}
END
)
response=$(curl -s -H "Content-Type: application/json" \
  -X POST \
  --data "$data" \
  -H "$session_token" \
  http://localhost:8080/certificate/revoke)

echo $response
