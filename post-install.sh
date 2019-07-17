#!/usr/bin/env bash

if [ -f "/etc/cron.d/acmetool" ]; then
  echo "Removing acmetool cron job from previous version"
  rm -f /etc/cron.d/acmetool
fi

/usr/local/bin/fleetssl-dnsonly
