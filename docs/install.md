# Install

## Requirements

- **OPNsense 25.7 or newer** - the login-page SSO button hook (`ISSOContainer` /
  `listSSOproviders`) landed in core in 25.7.
- For OpenVPN login: **OpenVPN 2.6+** on the firewall and a web-auth-capable client
  (OpenVPN Connect, OpenVPN 3 Linux, Windows 2.6+). Managed OpenVPN instances use
  client-certificate verification plus browser authentication; leave the instance's
  core **Authentication** field empty.
- An Identity Provider you control or use (Keycloak, Authentik, Entra ID, Zitadel, …).

## From the signed repository

This fork publishes a small repository containing only `os-sso`. It does not
replace or disable any OPNsense repository. The catalogue is signed with a dedicated
4096-bit RSA key; `pkg` verifies that signature before trusting package metadata.

The expected SHA-256 fingerprint of the repository public key is:

```text
3efc7a48172fb2f5efe0249de9064c771b902876e43332af28871a04b8b486e7
```

Install on **each HA node separately**. Repository configuration is local package-manager
state and must not be assumed to arrive through XMLRPC configuration sync:

```sh
fetch -qo /tmp/os-sso-bootstrap.sh https://jakduch.github.io/os-sso/bootstrap.sh
/bin/sh /tmp/os-sso-bootstrap.sh
rm -f /tmp/os-sso-bootstrap.sh
```

The script downloads the public key, checks the fingerprint above, installs
`/usr/local/etc/pkg/keys/jakduch-os-sso.pub` and
`/usr/local/etc/pkg/repos/JakduchOSSSO.conf`, refreshes catalogues, installs the plugin,
and registers it with the OPNsense firmware subsystem.

Verify the result:

```sh
pkg -vv | sed -n '/Repositories:/,$p'
pkg rquery -r JakduchOSSSO '%n-%v %R' os-sso
pkg info os-sso
```

Releases up to `v2026.10.8` used the package name `os-sso-devel`. The bootstrap detects
that package, removes it and installs `os-sso`. Configuration under `OPNsense/SSO` in
`/conf/config.xml` remains intact. The removal hook stops managed OpenVPN instances and
the installation hook synchronizes and starts them again, so perform the replacement in
a maintenance window even though no configuration is discarded.

For that one-time replacement, download and run the dedicated reinstall wrapper:

```sh
fetch -qo /tmp/os-sso-reinstall.sh https://jakduch.github.io/os-sso/reinstall.sh
/bin/sh /tmp/os-sso-reinstall.sh
rm -f /tmp/os-sso-reinstall.sh
```

For an HA update, upgrade the backup first, confirm its WebGUI/SSO/OpenVPN health, then
upgrade the master and test one controlled failover:

```sh
pkg update -f
pkg upgrade os-sso
/usr/local/opnsense/scripts/firmware/register.php install os-sso
```

The repository has ABI-specific catalogues at `pkg/FreeBSD:14:amd64` and
`pkg/FreeBSD:15:amd64`; `${ABI}` in the repository configuration selects the correct one
automatically.

OPNsense treats manually added third-party repositories and their packages as outside
official support. Keep a tested local administrator account and console access before
upgrading authentication software.

## From a release asset

Each release ships one package per FreeBSD ABI. Download the one matching your firewall's
base from [GitHub Releases](https://github.com/jakduch/os-sso/releases) - check it with
`pkg config ABI` (e.g. `FreeBSD:14:amd64` → the `…-FreeBSD-14.pkg`), then install:

```sh
pkg delete -y os-sso-devel              # only when the old package is installed
pkg add os-sso-*-FreeBSD-14.pkg         # pick the file matching your ABI
/usr/local/opnsense/scripts/firmware/register.php install os-sso
```

Then reload the WebGUI (or reboot). The new server types appear under
**System ▸ Access ▸ Servers**.

The registration command is needed after a direct local `pkg add`. OPNsense normally
runs the same step through its firmware installer; without it, the package is installed
and functional but the firmware page labels it `misconfigured`. A locally supplied
package continues to show `unknown-repository` (or `orphaned`) until the signed
repository is configured; that label does not affect the plugin runtime.

## Firmware upgrades and removal

The durable plugin configuration lives under `OPNsense/SSO` in `/conf/config.xml`.
OPNsense package removal deletes the plugin files, not that configuration branch, so a
firmware upgrade that temporarily drops the package does not erase providers, profiles
or their assignments. They return when a compatible package is installed again, and the
same data is included in a normal OPNsense configuration backup.

The code and authentication endpoints are unavailable while the package is missing.
Before removal, the package stops the OpenVPN fail-closed guard and every managed
OpenVPN instance; their saved directives deliberately remain so a manual restart cannot
silently fall back to certificate-only access. Files below `/var/db/os-sso*` are runtime
sessions, caches and locks, not durable configuration, and may be recreated or lost.

## Remove the third-party repository

Removing the repository does not uninstall the plugin:

```sh
rm -f /usr/local/etc/pkg/repos/JakduchOSSSO.conf
rm -f /usr/local/etc/pkg/keys/jakduch-os-sso.pub
pkg update -f
```

To remove the plugin as well, use the OPNsense firmware page or `pkg delete
os-sso`. The package's pre-deinstall hook stops managed OpenVPN instances rather
than allowing them to continue with a missing web-auth verifier.

## From source

`make package` on an OPNsense development VM, or the
`.github/workflows/build-pkg.yml` job CI runs on a `v*.*.*` tag.
