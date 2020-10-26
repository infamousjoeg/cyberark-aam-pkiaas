#!/bin/bash
set -e

main () {
    if [[ "$1" == "up" ]]; then
        echo "==> Starting Demo Environment"
        compose_up
    elif [[ "$1" == "down" ]]; then
        echo "==> Stopping Demo Environment"
        compose_down
    elif [[ "$1" == "restart" ]]; then
        echo "==> Restarting Demo Environment"
        compose_down
        compose_up
    else
        echo "Usage: $ ""$0"" [up/down/restart]"
        exit 1
    fi

    source_tester
}

compose_up () {
    docker-compose up --build -d && echo -n "==> Configuring" && until [[ -z $(docker ps | grep configurer) ]]; do sleep 1 && echo -n "."; done
}

compose_down () {
    docker-compose down --remove-orphans -v
}

source_tester () {
    stdout=$(docker-compose exec pkiaas-tester source /app/env/pkiaas.env)
    if [[ $stdout != "" ]]; then
        echo "Error occured setting environment variables. Exiting..."
        exit 1
    fi
}

main "$@"