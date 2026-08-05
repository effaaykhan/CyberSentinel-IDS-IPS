#!/bin/sh
# Register the unit, matching what cargo-deb generates for the .deb.
#
# The service is enabled but deliberately NOT started: a sensor should begin
# watching once its operator has reviewed the installed config, not because a
# package manager decided for them. `capture.enabled` ships false for the same
# reason.
systemctl daemon-reload >/dev/null 2>&1 || :
systemctl enable cybersentinel.service >/dev/null 2>&1 || :
