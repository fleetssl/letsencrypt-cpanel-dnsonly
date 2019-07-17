#!/usr/bin/env bash

if [ -f "/etc/cron.d/acmetool" ]; then
  echo "Removing acmetool cron job from previous version"
  rm -f /etc/cron.d/acmetool
fi

chmod 0644 /etc/cron.d/fleetssl-dnsonly

/usr/local/bin/fleetssl-dnsonly
