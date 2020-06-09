#!/bin/bash
set -e pipefail

REPO_NAME='cyberark-aam-pkiaas'

main () {
    download_conjur
    generate_masterkey
    start_conjur
    sleep 8
    conjur_createacct
    conjur_init
    conjur_authn
}

download_conjur () {
    # Download Conjur & pull Docker Images necessary
    curl -o docker-compose.yml https://raw.githubusercontent.com/infamousjoeg/conjur-install/master/docker-compose.yml
    docker-compose pull
}

generate_masterkey () {
    # Generate a secure master key for Conjur
    docker-compose run --no-deps --rm conjur data-key generate | sudo tee data_key > /dev/null
    DATA_KEY="$(< data_key)"
    sed -e "s#CONJUR_DATA_KEY:#CONJUR_DATA_KEY: ${DATA_KEY}#" docker-compose.yml > docker-compose-new.yml
    mv -f docker-compose-new.yml docker-compose.yml
    export CONJUR_DATA_KEY="${DATA_KEY}"
    rm -rf data_key
}

start_conjur () {
    # Spin up Docker containers for Conjur
    docker-compose up -d
    rm -rf docker-compose.yml
    # Wait for Conjur container to report healthy status
    until [ "$(docker inspect -f "{{.State.Status}}" "${REPO_NAME}_conjur_1")" == "running" ]; do
        sleep 0.1;
    done;
}

conjur_createacct () {
    # Configure Conjur & create account
    CONJUR_INFO=$(docker exec -i "${REPO_NAME}"_conjur_1 conjurctl account create quick-start)
    echo "${CONJUR_INFO}" > conjur_info
    export CONJUR_INFO="${CONJUR_INFO}"
}

conjur_init () {
    # Initialize Conjur
    API_KEY=$(echo "${CONJUR_INFO}" | awk 'FNR == 10 {print $5}')
    echo "${API_KEY}" > admin_api_key
    export CONJUR_ADMIN_API_KEY="${API_KEY}"
    docker exec -i "${REPO_NAME}"_client_1 conjur init -u conjur -a quick-start 
}

conjur_authn () {
    # Login to Conjur from CLI (Client) container for Admin user
    docker exec -i "${REPO_NAME}"_client_1 conjur authn login -u admin <<< "${CONJUR_ADMIN_API_KEY}"
}

main "$@"
