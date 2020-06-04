#!/bin/bash
util_defaults="set -u"

function conjur_verbose {
  if [ "${CONJUR_VERBOSE}" = "true" ]; then
    echo "-v"
  fi
}
verbose=$(conjur_verbose)

# this will return the authorization header used for api calls for other methods
function conjur_authenticate {
	$util_defaults
    api_key=$(curl $verbose --fail -s -k --user "$CONJUR_AUTHN_LOGIN:$CONJUR_AUTHN_API_KEY" $CONJUR_APPLIANCE_URL/authn/$CONJUR_ACCOUNT/login)
	session_token=$(curl $verbose --fail -s -k --data "$api_key" $CONJUR_APPLIANCE_URL/authn/$CONJUR_ACCOUNT/$CONJUR_AUTHN_LOGIN/authenticate)
	token=$(echo -n $session_token | base64 | tr -d '\r\n')
	header="Authorization: Token token=\"$token\""
	echo "$header"
}

function conjur_info {
	$util_defaults
	curl $verbose --fail -s -k "${CONJUR_APPLIANCE_URL}/info"
}

function conjur_health {
	$util_defaults
	curl $verbose --fail -s -k "${CONJUR_APPLIANCE_URL}/health"
}

function conjur_enable_authn {
	$util_defaults
	serviceID=$1
	header=$(conjur_authenticate)
	response=$(curl -H "$header" -X PATCH -d "enabled=true" -s -k "${CONJUR_APPLIANCE_URL}/${serviceID}/${CONJUR_ACCOUNT}")
	echo "$response"
	conjur_info
}

function conjur_audit {
	$util_defaults
	header=$(conjur_authenticate)
	response=$(curl -H "$header" -s -k "${CONJUR_APPLIANCE_URL}/audit")
	echo "$response"
}

function conjur_append_policy {
	$util_defaults
	policy_branch=$1
	policy_name=$2
	header=$(conjur_authenticate)
	response=$(curl -H "$header" -X POST -d "$(< $policy_name)" -s -k $CONJUR_APPLIANCE_URL/policies/$CONJUR_ACCOUNT/policy/$policy_branch)
	echo "$response"
}

function conjur_update_policy {
	$util_defaults
	policy_branch=$1
	policy_name=$2
	header=$(conjur_authenticate)
	response=$(curl -H "$header" -X PATCH -d "$(< $policy_name)" -s -k $CONJUR_APPLIANCE_URL/policies/$CONJUR_ACCOUNT/policy/$policy_branch)
	echo "$response"
}

function conjur_set_variable {
	$util_defaults
	variable_name=$1
	variable_value=$2
	header=$(conjur_authenticate)
	curl -k -s -H "$header" --data "$variable_value" "$CONJUR_APPLIANCE_URL/secrets/$CONJUR_ACCOUNT/variable/$variable_name"
}

function conjur_get_variable {
	$util_defaults
	variable_name=$1
	header=$(conjur_authenticate)
	value=$(curl -k -s -H "$header" "$CONJUR_APPLIANCE_URL/secrets/$CONJUR_ACCOUNT/variable/$variable_name")
	echo "${value}"
}

function conjur_resources {
  	$util_defaults
	header=$(conjur_authenticate)
	curl -k -s -H "$header" "$CONJUR_APPLIANCE_URL/resources/$CONJUR_ACCOUNT" | jq
}

function conjur_list {
	$util_defaults
	resources=$(conjur_resources)
	echo "${resources}" | jq -r .[].id
}

function conjur_rotate_api_key {
	$util_defaults
	$kind
}