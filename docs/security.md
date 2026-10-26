# Security model

What os-sso refuses, and why. The [unit suite](../test/README.md) covers exactly this:
every case is a refusal - the part an end-to-end run never reaches.

This document describes implemented controls, not a claim that the plugin is free of
vulnerabilities. It is an independently maintained third-party plugin; see
[`SECURITY.md`](../SECURITY.md) for private reporting and [`NOTICE.md`](../NOTICE.md)
for attribution and support status.

## Package trust

Release catalogues are signed with a repository-specific 4096-bit RSA key. The public
key is committed to the source tree and its SHA-256 fingerprint is printed in the
installation guide. The signing key is held only as a protected GitHub Environment
secret and is not part of the repository or package. Workflow dependencies are pinned
to exact commits, locked Composer dependencies are audited before packaging, and a
release is built separately for each supported FreeBSD ABI.

This signature authenticates packages produced by this fork. It does not make the fork
an official OPNsense repository or extend Deciso support to it.

## Sessions

Privileges are never stored in the session - the OPNsense ACL resolves them from group
membership on every request. A new session regenerates its ID (anti session-fixation). A
**disabled or expired** account is refused before group sync writes anything - on the
WebGUI, on the VPN, and on the captive portal, which needs no local account but will not
let a revoked one onto the network either.

The WebGUI timeout is *idle*-only; **Maximum session lifetime** is the absolute one, and
applies to the portal client and the VPN tunnel too (capped at 24 h there). It is enforced
by the **os-sso: expire SSO sessions** cron job, which the plugin schedules for itself
every 10 minutes.

## Account binding

An asserted identity binds only to an account os-sso owns or one with no usable local
password - never to one with a real password, and never to a privileged account
(`root`/system, `admins`) it did not create. A scrambled password is *not* ownership: that
is the WebGUI's own "no local login" checkbox, which LDAP-backed administrators wear.
Email matching additionally requires a verified address.

Display name and (verified) address are refreshed from the assertion on every login, on
the accounts os-sso owns. Nothing else is: a shell is how an account gets SSH, `expires`
is the operator's own lever, and API keys are separate credentials - none of them is a
directory's to set.

Each account is bound to **one subject per provider**, recorded on first login. A second
subject of the same provider presenting that account's username is refused - the takeover
a mutable username claim would otherwise allow.

**Strict account binding** decides whether a second *provider* may bind alongside, per
server, because nothing in the configuration distinguishes the two shapes it decides
between: one directory behind two authentication servers (the same person arriving over
OIDC and over SAML, where binding alongside is the whole point), and two unrelated
directories, where a user of one presenting a username from the other would inherit their
account and its groups. On - the default for a newly added server - a provider only binds
to an account no other one has claimed, by a previous login *or* by a SCIM push, so an
account a directory pre-provisioned and nobody has logged into yet is already spoken for.
It governs only a first-time match by username or verified email; the durable subject
stamp resolves either way.

## Groups

An OPNsense group carrying **any ACL privilege** only ever gains members through an
explicit operator mapping or default group; the 1:1 name fallback and SCIM refuse it.
That avoids treating a presently narrow page privilege as harmless directory data and
silently widening access later when OPNsense changes the ACL. **Strict group sync**
revokes only what os-sso granted, never a hand-assigned group, never the last member of
an escalation-equivalent group. Off, it is purely additive.

## Protocols

OIDC validates `iss`/`sub`/`aud`/`azp`/`nonce`/`exp`/`iat`, requires the stable `sub` to
be a non-empty OIDC identifier, binds `at_hash` to the access token and requires an
asymmetric signature; SAML verifies the assertion signature and is replay-protected
(single-use request id plus a consumed-assertion cache).

What the IdP is *asked* for is also *checked* on return - `max_age` against `auth_time`
(SAML: `AuthnInstant`), the required `acr` against the returned one - because requesting an
MFA context is voluntary per the spec, so only the answer proves anything.

The client can authenticate to the token endpoint with no shared secret at all
(`private_key_jwt`, mutual TLS), and the pre-auth endpoints are rate limited per source
(per /64 in IPv6). A login endpoint only answers a request the browser reports as a
top-level navigation, so a third-party page cannot start one - or, on the forward-auth
path where the proxy adds the token to whatever goes through it, complete one - from an
`<img>` tag.

## The Base URL

**Base URL** matters more than it looks: every URL the IdP is given is built from it, and
the fallback would trust the request `Host`. An IdP doing wildcard redirect matching plus a
forged `Host` header is how an authorization code ends up somewhere else. Mind a reverse
proxy or port-forward; the form shows the exact redirect/ACS URL to copy into the IdP.

## Revocation reaches all three doors

A back-channel logout, a SAML Single Logout, a SCIM `active: false`, "deprovision on
refused login" and the *End* button on the diagnostics page all act on the same record of
what os-sso granted - so they end the WebGUI session, disconnect the captive-portal client
from the network, and drop the OpenVPN tunnels of that client username, rather than only the
first of the three.

A deprovisioning is also **undone** by the login that disproves it: put the account back
in the required group at the IdP and the next login re-enables it, on all three doors,
rather than leaving somebody to tick the box back by hand. Only a refusal os-sso itself
issued is undone - it stamps the accounts it disables, and drops that stamp the moment it
sees one enabled again, so the operator's own *disabled* checkbox and `expires` date are
never overruled.

## Credentials and break-glass

`client_secret`, client keys and SP keys live in `config.xml` like other OPNsense
credentials (LDAP bind passwords and the like) and are never written to logs.

The local password (+ native TOTP) always stays active as a **break-glass** path: keep at
least one local admin.

For a managed OpenVPN profile, os-sso owns the instance's deferred-auth directive and a
supervised guard verifies the saved and generated configuration once per second. A managed
instance is stopped if the directive disappears or another password verifier appears
alongside it; it is restarted only after its own authentication settings validate. The configuration
event is asynchronous, so the guard is a periodic mitigation, not a synchronous pre-start
barrier. New VPN logins fail when
the IdP is unavailable. Existing tunnels remain subject to the recorded session lifetime and revocation.
Managed SSO instances refuse native OpenVPN authentication tokens, as described below.

[SCIM](scim.md) needs a bearer token **and** a source-address allowlist, and refuses on the
same principles as the login path.

## Configuration transactions and revocation failures

SSO provisioning and SCIM writes take the same configuration transaction lock as core
GUI writes. Conditional SCIM updates check their entity tag under that lock, and an
explicit SCIM activation/deactivation clears any earlier automatic-revival marker.

A failed VPN or captive-portal disconnect keeps its registry entry marked for retry.
The next session sweep retries it even if its original lifetime has not expired; the
scheduled sweep runs every ten minutes, and successful SSO logins also trigger it.
The recorded count includes acknowledged revocations only. VPN grants must be persisted
before a positive deferred-auth verdict is sent.

SAML assertion replay markers last through the signed SubjectConfirmation expiry plus
clock tolerance. The shorter login-request TTL does not limit replay protection. Legacy
markers without an expiry remain retained rather than being discarded unsafely.

VPN revocation resolves the exact client `Username` from OpenVPN management `status 3`,
then sends `client-kill` with numeric client IDs. Certificate common names can differ
from usernames. Incomplete, malformed or timed-out management responses retain the
grant for retry rather than acknowledging a disconnect.

Managed VPN instances reject `auth-gen-token` because OpenVPN accepts these credentials
without consulting the SSO hook on reconnect. A configured token lifetime, including
`0`, blocks profile application and keeps the instance stopped during guard repair.
Manually wired instances must omit this directive as well. Revocation sends the
`AUTH_FAILED` control message rather than requesting an automatic client restart.

## Browser session and logout lifecycle

WebGUI authentication requires an active native PHP file session, successful session-ID
rotation and a durable registry entry. Failure destroys the pending browser session.
The final account check and registry write run under the OPNsense configuration lock,
so an earlier provisioning decision cannot override a concurrent account deactivation.
PHP session directories configured as `N;[MODE;]/path` retain their native layout.

New grants pin an existing local account by UID, name and, where present, its UUID.
Removal, rename or replacement ends that grant at the next sweep. Portal guests who
never had a local account remain supported. Older WebGUI and VPN grants still require
their named account; legacy portal grants lack enough information to distinguish an
already-removed account from an accountless guest and retain their original expiry.

Validated logout messages are restricted to their configured provider and to every
subject/session identifier supplied. SAML front-channel logout also checks the current
browser's authentication method, provider, NameID and supplied SessionIndexes.
OIDC logout tokens require typed `iat`, `exp`, `jti` and logout-event claims. Replay
markers cover the full accepted clock-skew window and are scoped by issuer and client.
JWT single-use markers remain consumed while incomplete or corrupt; a concurrent
request cannot sweep away another worker's unfinished marker.

Final VPN approval reloads the local account under the core configuration lock and
keeps that lock through grant persistence and the privileged verdict. A missing,
disabled or expired account is refused before the VPN backend is called. An exception
or uncertain verdict starts revocation immediately after releasing the configuration
lock; failed disconnects remain pending. Local inspect/verdict calls use bounded
10-second response and 3-second connect timeouts while the lock is held.
SCIM and automatic deprovisioning revoke grants by their recorded local UID, including
portal identities whose IdP username differs from the local account name. Older grants
retain the name-based fallback. Captive-portal replies must include both AUTHORIZED and
a non-empty string session ID; a state-only response is not a revocable grant.

A contradictory portal reply that still identifies a session creates a rollback intent
before attempting to disconnect it. A failed disconnect remains pending for the
sweeper; it is not logged as successful. When the session registry itself is unavailable,
the plugin attempts a direct disconnect and reports any missing acknowledgement.
