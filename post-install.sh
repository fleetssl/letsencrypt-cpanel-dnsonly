#!/usr/bin/env bash

if [ -f "/etc/cron.d/acmetool" ]; then
  echo "Removing acmetool cron job from previous version"
  rm -f /etc/cron.d/acmetool
fi

if [ -f "/etc/cron.d/fleetssl-dnsonly" ]; then
  echo "Removing legacy cronjob from previous version (superseded by systemd timer)"
  rm -f /etc/cron.d/fleetssl-dnsonly
fi

/bin/bash -c '$(which systemctl) daemon-reload'
/bin/bash -c '$(which systemctl) enable fleetssl-dnsonly.timer'
/bin/bash -c '$(which systemctl) start fleetssl-dnsonly.timer'

/usr/local/bin/fleetssl-dnsonly
