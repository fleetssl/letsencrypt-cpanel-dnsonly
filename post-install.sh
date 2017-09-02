#!/usr/bin/env bash

set -euf -o pipefail

DNSONLY_PREFIX=/usr/local/letsencrypt-cpanel-dnsonly

# Hook goes in libexec if it exists, otherwise lib
HOOK_PREFIX=/usr/lib/acme/hooks
if [ -d "/usr/libexec" ]; then
  HOOK_PREFIX=/usr/libexec/acme/hooks
fi
mkdir -p ${HOOK_PREFIX}

cp ${DNSONLY_PREFIX}/certificate-hook.sh ${HOOK_PREFIX}/

echo "!!! Please wait, configuring acmetool !!!"

${DNSONLY_PREFIX}/acmetool quickstart --response-file=${DNSONLY_PREFIX}/responses.yml 

echo "!!! Please wait, trying to issue certificate now !!!"

${DNSONLY_PREFIX}/acmetool want $(hostname)

echo "Done."
