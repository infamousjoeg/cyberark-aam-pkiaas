#!/bin/bash
set -e

export CONJUR_AUTHN_LOGIN="host/pki-admin"

export CONJUR_AUTHN_API_KEY="${CONJUR_PKI_ADMIN_API_KEY}"
export VERBOSE=""


source conjur_utils.sh
session_token=$(conjur_authenticate)
pki_url="http://pkiaas:8080"

export session_token="$session_token"

# create the self signed certificate
data='{
  "commonName": "cyberark.pki.local",
  "keyAlgo": "RSA",
  "keyBits": "2048"
}'
curl --fail -H "Content-Type: application/json" \
  -H "$session_token" \
  --data "$data" \
  $VERBOSE \
  $pki_url/ca/generate/selfsigned

# create a test template
data='{
  "templateName": "andrewsTemplate",
  "keyAlgo": "RSA",
  "keyBits": "2048"
}'
curl --fail -H "Content-Type: application/json" \
  -H "$session_token" \
  --data "$data" \
  $VERBOSE \
  $pki_url/template/create


# create a test certificate
data='{
  "commonName": "subdomain.example.com",
  "templateName": "andrewsTemplate",
  "ttl": 1
}'

response=$(curl --fail -v -H "Content-Type: application/json" \
  -H "$session_token" \
  --data "$data" \
  $VERBOSE \
  $pki_url/certificate/create)

echo "Response:::::::::: $response"


# parse the result and get the certificate serial number
serialNumber=$(echo "$response" | jq -r .serialNumber)
certificateResponse=$(echo "$response" | jq -r .certificate)

response=$(curl --fail -s -H "Content-Type: application/json" \
  -H "$session_token" \
  $VERBOSE \
  $pki_url/certificate/$serialNumber)

certificateReturned=$(echo "$response" | jq -r .certificate)

if [ "${certificateResponse}" != "${certificateReturned}" ]; then
  echo "ERROR: Certificate should match but does not!"
  return 1
fi

# revoke specific certificate
data=$(cat <<-END
{
  "serialNumber": "$serialNumber"
}
END
)
response=$(curl --fail -s -H "Content-Type: application/json" \
  -X POST \
  --data "$data" \
  -H "$session_token" \
  $VERBOSE \
  $pki_url/certificate/revoke)


# certificate list
response=$(curl --fail -s -H "Content-Type: application/json" \
  -H "$session_token" \
  $pki_url/certificates)
echo "All your certifiates: $response"


# Lets revoke all the certificates that exists
for serialNumber in $(echo "${response}" | jq '.["certificates"]' | jq -r -c '.[]'); do
    data="{\"serialNumber\": \"$serialNumber\"}"
	response=$(curl --fail -s -H "Content-Type: application/json" \
		-X POST \
		--data "$data" \
		-H "$session_token" \
    $VERBOSE \
		$pki_url/certificate/revoke)
	echo "revoked $serialNumber and response was $response"
done

# Lets look at the CRL
response=$(curl --fail -s \
  $pki_url/crl)
if [[ -z $response ]]; then
  echo "ERROR: CRL Should have content"
  return 1
fi

# LETS PURGE!
curl --fail -s -H "Content-Type: application/json" \
	-X POST \
	-H "$session_token" \
	$pki_url/purge


# Lets get our CA Certificate
curl --fail -s \
	$pki_url/ca/certificate

# Lets get the CA chain
# TODO CURRENTLY THIS IS RETURNING A 500
# response=$(curl --fail -s \
# 	$pki_url/ca/chain)
# echo "CA CHAIN"
# echo "$response"


# Lets play with the templates
# list the templates
response=$(curl --fail -s \
	-H "$session_token" \
	$VERBOSE \
	$pki_url/templates)

# parse first template name (Should be only)
templateName=$(echo "$response" | jq  '.["templates"]' | jq -r '.[0]')

# get a specific template
curl --fail -s \
	-H "$session_token" \
	$VERBOSE \
	"$pki_url/template/$templateName"

# delete that same template we just examined
curl --fail -s \
	-H "$session_token" \
	-X "DELETE" \
	$VERBOSE \
	"$pki_url/template/delete/andrewsTemplate"


# re-create same template so I can test manually
# data='{
#   "templateName": "testingTemplate",
#   "keyAlgo": "RSA",
#   "keyBits": "2048"
# }'
# curl --fail -H "Content-Type: application/json" \
#   -H "$session_token" \
#   --data "$data" \
#   $pki_url/template/create
