# Security policy

## Supported releases

Security fixes are made on the current release line published by this fork. Install the
latest package available from the signed repository before reporting a problem. Older
packages and arbitrary source snapshots do not receive backports.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability, secrets, configuration
exports, tokens, certificates, or exploit details. Use GitHub's **Report a
vulnerability** flow under the repository's **Security** tab to create a private
security advisory for `jakduch/os-sso`.

Include the plugin version, OPNsense version, affected authentication protocol or
service, a minimal reproduction, and the security impact. Remove real credentials and
personal data.

## Scope and guarantees

This is authentication software running on a firewall, but it is still an independent
third-party plugin. Automated dependency, static-analysis and unit checks reduce risk;
they do not prove the absence of vulnerabilities. See
[`docs/security.md`](docs/security.md) for the implemented trust boundaries and
[`NOTICE.md`](NOTICE.md) for project ownership and support status.
