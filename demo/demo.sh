#!/bin/bash
set -ex

# THIS SHOULD BE RUN FROM WITHIN THE PKIAAS-TESTER CONTAINER

export CONJUR_AUTHN_LOGIN="host/pki-admin"
export CONJUR_AUTHN_API_KEY="${CONJUR_PKI_ADMIN_API_KEY}"

source /app/demo/conjur_utils.sh

session_token=$(conjur_authenticate)
export session_token="$session_token"
pki_url="http://pkiaas:8080"

main () {
    create_selfsigned_cert
    create_template
    create_certificate
    return_certificate
    revoke_certificate
    list_certificates
    revoke_all_certificates
    show_crl
    purge_crl
    show_cacert
    list_templates
    template_details
    delete_template
    create_ssh_template
    ssh_template_details
    ssh_list_templates
    ssh_update_template
    create_ssh_certificate
}

create_selfsigned_cert () {
    data='{
        "commonName": "cyberark.pki.local",
        "keyAlgo": "RSA",
        "keyBits": "2048"
    }'
    curl  -H "Content-Type: application/json" \
        -H "$session_token" \
        --data "$data" \
        "$pki_url"/ca/generate/selfsigned
}

create_template () {
    data='{
        "templateName": "demoTemplate",
        "keyAlgo": "RSA",
        "keyBits": "2048"
    }'
    curl --fail -H "Content-Type: application/json" \
        -H "$session_token" \
        --data "$data" \
        "$pki_url"/pki/template
}

create_certificate () {
    data='{
        "commonName": "subdomain.example.com",
        "templateName": "demoTemplate",
        "ttl": 1
    }'

    response=$(curl --fail -v -H "Content-Type: application/json" \
        -H "$session_token" \
        --data "$data" \
        "$pki_url"/pki/certificate/create)

    echo "==> Create Certificate Response"
    echo "$response"
}

return_certificate () {
    serialNumber=$(echo "$response" | jq -r .serialNumber)
    certificateResponse=$(echo "$response" | jq -r .certificate)

    response=$(curl --fail -s -H "Content-Type: application/json" \
        -H "$session_token" \
        "$pki_url"/pki/certificate/"$serialNumber")

    certificateReturned=$(echo "$response" | jq -r .certificate)

    if [ "${certificateResponse}" != "${certificateReturned}" ]; then
        echo "ERROR: Certificate should match but does not!"
        return 1
    fi

    echo "==> Return Certificate Response"
    echo "$response"
}

revoke_certificate () {
    data=$(cat << EOF
{
    "serialNumber": "$serialNumber"
}
EOF
    )
    curl --fail -s -H "Content-Type: application/json" \
        -X POST \
        --data "$data" \
        -H "$session_token" \
        "$pki_url"/pki/certificate/revoke
}

list_certificates () {
    response=$(curl --fail -s -H "Content-Type: application/json" \
        -H "$session_token" \
        "$pki_url"/pki/certificates)
    echo "==> List Certificates Response"
    echo "$response"
}

revoke_all_certificates () {
    for serialNumber in $(echo "${response}" | jq '.["certificates"]' | jq -r -c '.[]'); do
        data="{\"serialNumber\": \"$serialNumber\"}"
        response=$(curl --fail -s -H "Content-Type: application/json" \
            -X POST \
            --data "$data" \
            -H "$session_token" \
            "$pki_url"/pki/certificate/revoke)
        echo "==> Revoked ""$serialNumber"" Response"
        echo "$response"
    done
}

show_crl () {
    response=$(curl --fail -s \
        "$pki_url"/pki/crl)
    if [[ -z "$response" ]]; then
        echo "ERROR: CRL Should have content"
        return 1
    fi
    echo "==> Show CRL Response"
    echo "$response"
}

purge_crl () {
    curl --fail -s -H "Content-Type: application/json" \
        -X POST \
        -H "$session_token" \
        "$pki_url"/pki/purge
}

show_cacert () {
    response=$(curl --fail -s "$pki_url"/ca/certificate)
    echo "==> Show CA Certificate Response"
    echo "$response"
}

list_templates () {
    response=$(curl --fail -s \
        -H "$session_token" \
        "$pki_url"/pki/templates)
    echo "==> List Templates Response"
    echo "$response"
}

template_details () {
    templateName=$(echo "$response" | jq  '.["templates"]' | jq -r '.[0]')
    response=$(curl --fail -s \
        -H "$session_token" \
        "$pki_url"/pki/template/"$templateName")
    echo "==> Template Details for $templateName"
    echo "$response"
}

delete_template () {
    curl --fail -s \
        -H "$session_token" \
        -X "DELETE" \
        "$pki_url"/pki/template/"$templateName"
    echo "==> Deleted Template $templateName"
}

create_ssh_template () {
    data='{
        "templateName": "sshTemplate",
        "certType": "Host",
        "maxTTL": 36000
    }'
    curl --fail -H "Content-Type: application/json" \
        -H "$session_token" \
        --data "$data" \
        "$pki_url"/ssh/template
}

ssh_template_details () {
    response=$(curl -fail -H "$session_token" \
        "$pki_url"/ssh/template/sshTemplate)
    echo "==> SSH Template Details Response for sshTemplate"
    echo "$response"
}

ssh_list_templates () {
    response=$(curl -fail -H "$session_token" \
    "$pki_url"/ssh/templates)
    echo "==> List SSH Templates Response"
    echo "$response"
}

ssh_update_template () {
    curl --fail -H "$session_token" \
        -H "Content-Type: application/json" \
        -X "PUT" \
        --data "$data" \
        "$pki_url"/ssh/template
}

create_ssh_certificate () {
    data='{
        "templateName": "sshTemplate",
        "publicKey": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDC8BqsuevltRlMFOGCW3dZsVFGRjD7AgO83A0zE/3a0/Zd1YFAwp4a3LwBE3xu2+e3oRCyb9ibU1BZeEGXxByTy+jyS21R5TLmMEOkOB3CHO3Mo1Fm5f12PKalMhXcoEALiJVm5zpBDlDmzi+bExLWkZaLp5lN06HA72k8dfZoD35PzaLOxWRkXhVrJHz9tkas7kwmuykdyZFjffveUCuFBFtcY2XTeZV3YZHjTfttw+bFAsjSB9VNJif/7Ejw7mv0HDD+sbEHJCrS+VYwiYUaipD9BLmBVPKmvNtIj/7EUF3NypqfRhxjlNEPEfrQJAW4z4/QMyVssy3FXW3QrYC1 root@ip-10-0-20-126"
    }'
    curl --fail -H "$session_token" \
        -H "Content-Type: application/json" \
        --data "$data" \
        "$pki_url"/ssh/certificate/create
}

main "$@"