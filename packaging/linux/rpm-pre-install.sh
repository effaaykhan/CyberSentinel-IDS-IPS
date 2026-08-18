#!/bin/sh
# The RPM half of the pre-0.2.0 unit rename. See maintainer/preinst.
#
# $1 is 2 on the install half of an upgrade and 1 on a first install, so this
# only runs where an older version could have left `cybersentinel.service`
# enabled. The old package's %preun runs later in an upgrade and deliberately
# does nothing ($1 = 1), so retiring the old unit has to happen here.
if [ "$1" = 2 ]; then
    systemctl --no-reload disable --now cybersentinel.service >/dev/null 2>&1 || :
fi
