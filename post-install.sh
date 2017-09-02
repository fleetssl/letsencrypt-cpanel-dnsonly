#!/usr/bin/env bash

set -euf -o pipefail

DNSONLY_PREFIX=/usr/local/letsencrypt-cpanel-dnsonly

mkdir -p /usr/lib/acme/hooks/
cp ${DNSONLY_PREFIX}/certificate-hook.sh /usr/lib/acme/hooks/

echo "!!! Please wait, configuring acmetool !!!"

${DNSONLY_PREFIX}/acmetool quickstart --response-file=${DNSONLY_PREFIX}/responses.yml 

echo "!!! Please wait, trying to issue certificate now !!!"

${DNSONLY_PREFIX}/acmetool want $(hostname)

echo "Done."
