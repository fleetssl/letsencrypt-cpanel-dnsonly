#!/usr/bin/env bash

if [ ! -f "/usr/sbin/whmapi1" ]; then
    echo "Cannot find cPanel installed (whmapi1 command missing). FAILED.";
    exit 1;
fi

host $(hostname)
if [ $? -ne 0 ]; then
    echo "Hostname '$(hostname)' doesn't seem to resolve, at least according to this server. The server hostname must be a FQDN and resolve on the internet before this package may be installed. Please see https://documentation.cpanel.net/display/ALD/Change+Hostname ."
    exit 1;
fi
