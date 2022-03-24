#! /usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

function check_env() {
    if [[ ! -v $1 ]]; then
        echo >&2 "Need to define $1 as an environment variable"
        exit 1
    fi
}

function check_installed() {
    if ! command -v $1 > /dev/null; then
        echo >&2 "Looks like $1 isn't installed; you will need to install it before you can use this script."
        exit 1
    fi
}

function do_update() {
    check_installed curl
    check_installed base64

    local url="https://api.dynamicip.link/link/${LINK_DOMAIN}"
    local targetip=$(curl -s https://icanhazip.com)
    local auth=$(echo -n "${USERNAME}:${PASSWORD}" | base64)

    curl -s -H "Authorization: Basic ${auth}" -X PUT ${url} -d "target_ip=${targetip}" -d "foo=bar"
}

check_env LINK_DOMAIN
check_env USERNAME
check_env PASSWORD
do_update
curl -s https://hc-ping.com/7979011b-9243-4498-b393-a93c5442ada2 > /dev/null  || true # Let me know it's working
