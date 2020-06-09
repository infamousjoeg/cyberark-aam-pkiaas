#!/bin/bash
set -e pipefail

$REPO_NAME='cyberark-aam-pkiaas'

main () {
    download_conjur
    generate_masterkey
    start_conjur
    sleep 8
    conjur_createacct
    conjur_init
    conjur_authn
    report_info
    report_info > conjur_config
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
    until [ "$(docker inspect -f "{{.State.Status}}" "${REPO_NAME}_conjur_1)" == "running" ]; do
        sleep 0.1;
    done;
}

conjur_createacct () {
    # Configure Conjur & create account
    CONJUR_INFO=$(docker exec -i "${REPO_NAME}"_conjur_1 conjurctl account create quick-start)
    export CONJUR_INFO="${CONJUR_INFO}"
}

conjur_init () {
    # Initialize Conjur
    API_KEY=$(echo "${CONJUR_INFO}" | awk 'FNR == 10 {print $5}')
    export CONJUR_API_KEY="${API_KEY}"
    docker exec -i "${REPO_NAME}"_client_1 conjur init -u conjur -a quick-start 
}

conjur_authn () {
    # Login to Conjur from CLI (Client) container for Admin user
    docker exec -i "${REPO_NAME}"_client_1 conjur authn login -u admin <<< "${CONJUR_API_KEY}"
}

report_info () {
    # Report to STDOUT all pertinent info for Conjur
    CYAN='\033[0;36m'
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    NC='\033[0m' # No Color
    echo -e "${GREEN}+++++++++++++++++++++++++++++++++++++++++++++++++++++${NC}"
    echo -e "${RED}SAVE THESE VALUES IN A SAFE PLACE!${NC}"
    echo -e "${GREEN}+++++++++++++++++++++++++++++++++++++++++++++++++++++${NC}"
    echo -e "${CYAN}Conjur Data Key:${NC} ${YELLOW}${CONJUR_DATA_KEY}${NC}"
    echo -e "${CYAN}Conjur Public SSL Certificate & Admin API Key:${YELLOW}"
    echo -e "${CONJUR_INFO}"
    echo -e "${GREEN}+++++++++++++++++++++++++++++++++++++++++++++++++++++"
    echo -e "+++++++++++++++++++++++++++++++++++++++++++++++++++++"
    echo -e "${NC}Your Conjur environment is running in Docker: ${CYAN}sudo docker ps${NC}"
    docker ps
    echo -e "Interact with it via Conjur CLI on ${USER}_client_1: ${CYAN}sudo docker exec -it ${USER}_client_1 bash${NC}"
    echo -e "Once connected check your user: ${CYAN}conjur authn whoami"
    echo -e "${GREEN}+++++++++++++++++++++++++++++++++++++++++++++++++++++${NC}"
}

main "$@"
