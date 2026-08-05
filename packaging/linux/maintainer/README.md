# Debian maintainer scripts

Deliberately (almost) empty.

`cargo-deb` only generates the `postinst`/`prerm`/`postrm` that register the
systemd unit when `package.metadata.deb.maintainer-scripts` names a directory —
its `generate_scripts` returns early otherwise. With the key unset, the unit
file is installed and nothing ever runs `systemctl daemon-reload` or
`systemctl enable`, so the sensor does not start at boot. The package looks
correct in `dpkg-deb --contents`, which is what made it easy to miss.

So this directory exists to be named. Anything placed here is merged into the
generated scripts, and must contain a `#DEBHELPER#` token where the systemd
fragments should be inserted.

The equivalent RPM scriptlets are `../rpm-*.sh`, named directly from
`package.metadata.generate-rpm`.
