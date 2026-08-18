#!/bin/sh
# $1 is 0 on a real removal and 1 on the removal half of an upgrade. Stopping
# the sensor mid-upgrade would leave a gap in coverage for no reason.
if [ "$1" = 0 ]; then
    systemctl --no-reload disable --now cybersentinel-ips.service >/dev/null 2>&1 || :
fi
