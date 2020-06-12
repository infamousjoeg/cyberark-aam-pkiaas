#!/bin/bash
set -e
export CONJUR_APPLIANCE_URL=https://conjur-master
export CONJUR_AUTHN_LOGIN="host/pki-admin"
export CONJUR_CERT_FILE="$(pwd)/conjur.pem"
export CONJUR_ACCOUNT="conjur"
export CONJUR_AUTHN_API_KEY="18ybbxf2ytt4pr1j8tek739n3vsf34hxmpbw6fg8j1nqy15pp1nn5z"

source conjur_utils.sh
session_token=$(conjur_authenticate)
export session_token="$session_token"

# create a test certificate
data='{
  "commonName": "subdomain.example.com",
  "templateName": "testingTemplate2",
  "ttl": 3600
}'
response=$(time curl --fail -s -H "Content-Type: application/json" \
  -H "$session_token" \
  --data "$data" \
  http://localhost:8080/certificate/create)
echo $response
