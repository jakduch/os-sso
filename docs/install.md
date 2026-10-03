# Install

## Requirements

- **OPNsense 25.7 or newer** - the login-page SSO button hook (`ISSOContainer` /
  `listSSOproviders`) landed in core in 25.7.
- For OpenVPN login: an OPNsense core build with the `openvpn_instance_config` plugin hook,
  **OpenVPN 2.6+** on the firewall, and a web-auth-capable client
  (OpenVPN Connect, OpenVPN 3 Linux, Windows 2.6+). Managed OpenVPN instances use
  client-certificate verification plus browser authentication; leave the instance's
  core **Authentication** field empty.
- An Identity Provider you control or use (Keycloak, Authentik, Entra ID, Zitadel, …).

## From a release

Each release ships one package per FreeBSD ABI. Download the one matching your firewall's
base from the [Releases](../../../releases) page - check it with `pkg config ABI`
(e.g. `FreeBSD:14:amd64` → the `…-FreeBSD-14.pkg`), then install:

```sh
pkg add os-sso-devel-*-FreeBSD-14.pkg   # pick the file matching your ABI
/usr/local/opnsense/scripts/firmware/register.php install os-sso-devel
```

Then reload the WebGUI (or reboot). The new server types appear under
**System ▸ Access ▸ Servers**.

The registration command is needed after a direct local `pkg add`. OPNsense normally
runs the same step through its firmware installer; without it, the package is installed
and functional but the firmware page labels it `misconfigured`. A locally supplied
package continues to show `unknown-repository` (or `orphaned`) until it is served from a
configured package repository; that label does not affect the plugin runtime.

## Firmware upgrades and removal

The durable plugin configuration lives under `OPNsense/SSO` in `/conf/config.xml`.
OPNsense package removal deletes the plugin files, not that configuration branch, so a
firmware upgrade that temporarily drops the package does not erase providers, profiles
or their assignments. They return when a compatible package is installed again, and the
same data is included in a normal OPNsense configuration backup.

The code and authentication endpoints are unavailable while the package is missing.
Before removal, the package stops the OpenVPN fail-closed guard and every managed
OpenVPN instance. Removing the plugin also removes its generated authentication hook, so
review or disable those instances before starting them again. Files below `/var/db/os-sso*`
are runtime sessions, caches and locks, not durable configuration, and may be recreated or
lost.

## From source

`make package` on an OPNsense dev VM, or the `.github/workflows/build-pkg.yml` job CI runs
on a `v*.*.*` tag.
