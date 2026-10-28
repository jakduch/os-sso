# os-sso test lab

Two independent layers:

- **`unit/`** - the security-deciding logic, called directly. No dependency but PHP.
- **`e2e/`** - the real thing: a Vagrant OPNsense VM plus Authentik and Keycloak in
  Docker, driven through actual browser ceremonies.

## Unit tests

```sh
php unit/run.php                 # everything
php unit/run.php scim            # only matching suites
```

Covers what an end-to-end run never reaches, because every case is a *refusal*: which
local account an asserted identity may bind to, which group a directory may fill, what
counts as a same-site return URL, how the client authenticates to a token endpoint.

Several groups need `/var/db/os-sso` (where the config lock and the session registry
live) and report `skip` rather than fail without it, so the suite still runs
unprivileged. One case inside them additionally wants root and a `nobody` account, to
make that directory unusable the way `StateDir` itself judges it -- which is what proves
a captive-portal grant nothing can record is given back rather than kept. For the full
set, either:

```sh
docker run --rm -v "$PWD/..:/w" -w /w php:8.3-cli php test/unit/run.php
vagrant ssh -c 'cd /home/vagrant/os-sso && sudo php test/unit/run.php'
```

## Automated security checks

The `Test` workflow runs the PHP 8.3/8.5 unit suites, Python guard/revocation tests,
package/repository shell tests and concurrent writes against pinned OPNsense core
versions. These include native WebGUI session establishment in separate PHP processes.

The `Security` workflow runs for pull requests, main-branch pushes and weekly, and can
also be started manually. It runs Semgrep Community Edition on first-party PHP/Python
and CodeQL's extended security queries on Python and GitHub Actions. Both publish SARIF
findings into the repository's **Security → Code scanning** page and PR checks. Semgrep
findings still fail its scan step; publishing results does not hide a failed scan.
CodeQL does not support PHP. Dependency Review rejects new dependencies with known
vulnerabilities at low severity or above. Composer's locked-dependency audit remains in
`Test`. Dependabot security updates, secret scanning and secret push protection are
repository settings; a workflow file alone does not enable those settings.

The same workflow also runs these account-free CLI tools:

- **Psalm taint analysis** scans first-party PHP libraries, controllers, models and scripts.
  `security/framework.phpstub` models Phalcon request values/raw bodies as untrusted input,
  response headers/content as sinks, and configd action names as command sinks. Structured
  backend arguments are quoted by core; they are not modelled as raw shell commands.
  The reviewed `ReturnUrl::sanitize()` contract removes only header taint. It does not make
  a value safe for HTML. Five deliberately unsafe flows and three safe controls verify
  those assumptions before every scan. No taint baseline suppresses production findings.
- **Gitleaks CLI** scans all fetched Git history, with fully redacted SARIF reports.
  `.gitleaks.toml` keeps default rules and narrowly exempts only a public verification-key
  hash and the local lab issuer URL in their original files and the scanner self-test. A temporary-repository test
  verifies that adjacent synthetic tokens are detected even after a later commit removes
  them. These exceptions never exclude a complete test directory or commit.
- **Trivy** scans the runtime Composer lock against its current advisory database,
  including transitive dependencies, and fails on known vulnerabilities at low severity
  or above. It complements Composer audit and Dependency Review.

All reports are published to **Security → Code scanning**, including when a scan finds an
issue and fails. Tools are pinned in `security/tools.json`; `security/install_tool.py`
verifies each release asset's SHA-256 before extracting only its expected executable.
Update the version, URL and reviewed digest together when upgrading a scanner. No scanner
account, API token or paid service is required on this public repository's standard runners.

The framework model is focused on HTTP-to-output/backend taint paths. Other core services,
magic model fields, protocol validation and authorization decisions still need regression
and appliance tests. A zero-result scan is not proof that the plugin has no vulnerabilities.

The OPNsense VM/browser suites below remain a separate lab step. Static code scanning
and unit success do not substitute for running real VPN, portal and HA tests.

## Bringing the lab up

`vagrant up` is self-contained: it pushes the source over SCP and deploys the plugin into
the live tree, no manual steps.

```sh
vagrant up                            # boot the OPNsense VM + deploy the plugin
cd idp && ./up.sh                     # start Authentik + Keycloak (+ TLS proxy)
bash keycloak/setup-keycloak.sh       # create realm, clients, test user
bash authentik/setup.sh               # create OIDC/SAML providers + mappings
cd .. && vagrant/register-authservers.sh   # tell OPNsense about them
```

That last step is not optional and used to be missing: the setup scripts configure the
IdP, but nothing told OPNsense which authentication servers to offer. A VM that had been
around a while carried them in its `config.xml` from some earlier hand-registration, so
the gap only showed up on a freshly built box -- as most suites failing against a
provider that did not exist. It reads whatever the setup wrote (`/tmp/kc-out.env`,
`/tmp/authentik-out.env`), so it registers the values actually provisioned:

```sh
IDP=authentik vagrant/register-authservers.sh          # the other IdP
FORCE=1 vagrant/register-authservers.sh                # repair a wrong registration
```

An existing server is left alone by default -- the suites write their own settings onto
these (SCIM token, service scope, session lifetime) and recreating one mid-run discards
them. `FORCE=1` replaces it instead.

### Building the FreeBSD 15 box

`puzzle/opnsense` stops at 26.1 (FreeBSD 14, php83), so the php85 side of the matrix
needs a box built locally from the official image. Point the lab at it with `SSO_BOX`:

```sh
SSO_BOX=opnsense/26.7 vagrant up
SSO_BOX=opnsense/26.7 SSO_GUI_URL=https://192.168.60.10 e2e/run-all.sh
```

The box wants the Vagrant conventions OPNsense does not ship with: a `vagrant` user in
the **wheel** group (its sshd sets `AllowGroups wheel`, so a key is refused otherwise),
the insecure public key, passwordless sudo, and `bash` (Vagrant runs `bash -l`).

Host `/etc/hosts` needs `127.0.0.1 authentik.test keycloak.test`. The VM gets a host-only
address (`192.168.60.10`) *and* a NAT forward for the WebGUI; override either when
something already owns it:

```sh
SSO_LAN_IP=192.168.60.10 SSO_GUI_PORT=8444 vagrant up      # host-only + WebGUI forward
KC_HTTP_PORT=8091 ./up.sh keycloak                         # Keycloak admin port
SP_BASE=https://192.168.60.10 bash keycloak/setup-keycloak.sh
```

### One origin, end to end

`SP_BASE`, the auth server's **Base URL** and `SSO_GUI_URL` must all be the same string.
The OIDC/SAML anti-replay material (state, nonce, PKCE) lives in a session cookie, so a
login started on one origin with a callback landing on another will not find it.

Prefer the host-only address: the captive portal listens on `8000+zoneid` of the zone
interface and redirects there, which a NAT forward cannot reach. (192.168.60/24 rather
than the usual .56 because VMware takes `vmnet2`/`vmnet3` there, and VirtualBox only
allows host-only addresses inside 192.168.56.0/21 without `/etc/vbox/networks.conf`.)

## Running the suites

```sh
export SSO_GUI_URL=https://192.168.60.10       # must match the provider Base URL
e2e/run-all.sh                                 # everything, Keycloak
IDP=authentik e2e/run-all.sh                   # same, Authentik
e2e/run-all.sh oidc saml                       # a subset
e2e/oidc.sh                                    # or one suite on its own
```

| Suite | Where | Checks | Covers |
|---|---|---|---|
| `oidc.sh` | host | 45-46 | the browser ceremony, Host-header hardening, diagnostics + UI pages, logout CSRF, pushed authorization requests, rate limiting, required groups, deprovisioning *and the login that undoes it*, session expiry, back-channel logout, service scoping, ending a session from the diagnostics page |
| `saml.sh` | host | 16-21 | per-provider EntityID/ACS/SLO, assertion replay, IdP-initiated (off/on/off - Keycloak only), POST binding, metadata import, SLO |
| `portal.sh` | host | 11 | a captive client signing in, being authorized in its zone, and being disconnected again when its grant is revoked |
| `vpn-client.sh` | host | 5 | a real OpenVPN client: deferred auth, WEB_AUTH url, tunnel up after the browser login |
| `scim.sh` | host | 46 | discovery, bearer + source gate, user lifecycle, filters, the four refusals, session revocation on deactivate, and Authentik's real SCIM client |
| `jwt.sh` | VM | 17 | source gate, signature/aud, `iat`, max-age, single-use, group mapping |
| `cp.sh` | VM | 8 | the authorizer gates, CORS scoping, and a real configd allow |
| `vpn.sh` | VM | 23 | the hook and the verdict writer, profile resolution, IP binding, single-use session ids, username enforcement, the common name a revocation kills, stale-session sweep |

Host-side suites drive the whole ceremony through `e2e/lib/idp_login.py`, which speaks
both dialects: Keycloak renders a login form, Authentik drives a flow-executor API. They
run from any directory - each resolves its own location first, symlinks included - and say
so rather than failing blank if started from an incomplete copy.

`vpn-client.sh` needs `openvpn` on the host and the lab VPN server started with
`vagrant ssh -c 'sudo sh /home/vagrant/os-sso/test/vagrant/setup-vpn-server.sh'`; it skips
itself when openvpn is missing. See [vpn-client/README.md](vpn-client/README.md) for
driving the flow by hand with a real GUI client.

## When it breaks for the wrong reason

Three failure modes that look like plugin bugs and are not:

- **Clock drift.** A suspended VirtualBox guest drifts, and its NTP has no route out here
  (the WAN interface is disabled). Past the 60s signing leeway every login fails on the
  *token* - `Cannot handle token with iat prior to ...` - which reads like anything but a
  clock problem. `run-all.sh` resynchronises from the host before it starts; tune with
  `SSO_CLOCK_TOLERANCE` (default 5s), disable with `SSO_SKIP_CLOCK_SYNC=1`.
- **An enabled captive portal zone** installs pf `rdr` rules that intercept http/https on
  the LAN interface - the very origin the host-side suites use - so a leftover zone breaks
  the *next* run with a TLS handshake error. `cp.sh` and `portal.sh` disable their zones on
  the way out; `vagrant/disable_cp_zones.php` does it by hand.
- **Leftover account state.** `scim.sh` and the deprovisioning cases deliberately disable
  accounts. `vagrant/reset_sso_users.php` puts them back; `run-all.sh` does not, so a suite
  run on its own after another may find a disabled user.
