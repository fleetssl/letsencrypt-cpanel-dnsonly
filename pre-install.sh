#!/usr/bin/env bash

if [ ! -f "/usr/sbin/whmapi1" ]; then
    echo "Cannot find cPanel installed (whmapi1 command missing). FAILED.";
    exit 1;
fi
