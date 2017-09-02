#!/usr/bin/env bash

# This file is managed by the letsencrypt-cpanel-dnsonly package. Do not modify it, as your changes will be overwritten during upgrades.

set -euf -o pipefail

EVENT_NAME="$1"
[ "$EVENT_NAME" = "live-updated" ] || exit 42


# Credit: https://stackoverflow.com/a/10660730/1327984
rawurlencode() {
  local string="${1}"
  local strlen=${#string}
  local encoded=""
  local pos c o

  for (( pos=0 ; pos<strlen ; pos++ )); do
     c=${string:$pos:1}
     case "$c" in
        [-_.~a-zA-Z0-9] ) o="${c}" ;;
        * )               printf -v o '%%%02x' "'$c"
     esac
     encoded+="${o}"
  done
  echo "${encoded}"    # You can either set a return variable (FASTER) 
}

ACME_PREFIX=/var/lib/acme/live/$(hostname)

CRT=$(rawurlencode "$(cat ${ACME_PREFIX}/cert)")
KEY=$(rawurlencode "$(cat ${ACME_PREFIX}/privkey)")
CHAIN=$(rawurlencode "$(cat ${ACME_PREFIX}/chain)")

/usr/sbin/whmapi1 install_service_ssl_certificate service=cpanel crt="${CRT}" key="${KEY}" cabundle="${CHAIN}" && \ /sbin/service cpanel restart
