<?php

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use OPNsense\Core\Backend;

/**
 * Authorizes an OpenVPN deferred web-auth attempt, shared by the OIDC and SAML
 * controllers. OpenVPN's control file is root-owned while the WebGUI runs as www,
 * so the privileged write is delegated to configd (vpn_verdict.sh, root). The
 * auth-user-pass-verify script stored the {sid -> control file} mapping; the
 * verdict script resolves and consumes it (single use).
 */
final class VpnAuthorizer
{
    /**
     * @param string $vpn one-time VPN session id (hex)
     * @param string $username verified local username (for audit)
     * @param string $browserIp source IP of the browser completing the SSO login;
     *               must match the VPN client's IP (enforced by vpn_verdict.sh)
     * @return string the exact client username used to locate management client IDs
     * @throws \RuntimeException on an unknown session, ip mismatch, or failed write
     */
    public static function authorize(string $vpn, string $username, string $browserIp, array $idpSession = []): string
    {
		$handle = null;
		try {
			return ConfigLock::with(function () use ($vpn, $username, $browserIp, $idpSession, &$handle): string {
				return self::authorizeLocked($vpn, $username, $browserIp, $idpSession, $handle);
			});
		} catch (\Throwable $error) {
			// Cleanup can wait on a backend. Release the global configuration lock first.
			if ($handle !== null) {
				SessionRegistry::destroyById($handle);
			}
			throw $error;
		}
	}


	private static function authorizeLocked(string $vpn, string $username, string $browserIp, array $idpSession, ?string &$handle): string
	{
		$account = (new LocalAccountWriter())->findByName($username);
		if ($account === null) {
			throw new \RuntimeException('VPN authorization refused: local account is missing');
		}
		LocalAccount::assertUsable($account);
        $sid = preg_replace('/[^a-f0-9]/', '', $vpn);
        if ($sid === '') {
            throw new \RuntimeException('invalid VPN session');
        }
        $ip = preg_replace('/[^0-9a-fA-F.:]/', '', $browserIp);
        // The account that actually signed in, so the verdict script can log it next to
        // the username the client asked for -- and refuse the two differing when the
        // operator enabled that. Reduced to the local-account charset: this crosses
        // configd into a positional shell argument.
        $user = preg_replace('/[^A-Za-z0-9._\- ]/', '', $username);
        $backend = new Backend();
        $inspect = rtrim((string)$backend->configdpRun('sso vpn_inspect', [$sid, $ip, $user], false, 10, 3), "\r\n");
        $parts = explode(' ', $inspect, 2);
        $clientUsername = $parts[1] ?? '';
        if (($parts[0] ?? '') !== 'ok' || preg_match('/^[A-Za-z0-9._@ -]{1,64}$/D', $clientUsername) !== 1) {
            throw new \RuntimeException('VPN session cannot be inspected for revocation: ' . $inspect);
        }
        // Persist a revocable grant BEFORE writing a positive OpenVPN verdict.
        $handle = SessionRegistry::createGrant([
            'kind' => SessionRegistry::VPN,
            'username' => $username,
            'vpn_username' => $clientUsername,
        ] + $idpSession);
        if ($handle === null) {
            throw new \RuntimeException('VPN authorization refused: the grant could not be recorded');
        }
		// These local verdict scripts should finish promptly; bound the time for
		// which a stalled configd can keep all configuration writers waiting.
		$out = rtrim((string)$backend->configdpRun('sso vpn_verdict', [$sid, '1', $ip, $user], false, 10, 3), "\r\n");
		if ($out !== $inspect) {
			throw new \RuntimeException('VPN authorization failed: ' . $out);
		}
        syslog(LOG_NOTICE, sprintf("os-sso vpn: authorized tunnel for '%s' from %s", $username, $ip));
        return $clientUsername;
    }

    /** Minimal "close this window" page shown to the VPN client's browser. */
    public static function donePage(string $username): string
    {
        $u = htmlspecialchars($username, ENT_QUOTES);
        $title = htmlspecialchars(gettext('VPN authorized'), ENT_QUOTES);
        $body = sprintf(
            htmlspecialchars(gettext('Signed in as %s. You can close this window and return to your VPN client.')),
            '<strong>' . $u . '</strong>'
        );
        return "<!doctype html><html><head><meta charset='utf-8'><title>{$title}</title>"
            . "<style>body{font-family:sans-serif;text-align:center;margin-top:4em;color:#1b5e20}</style>"
            . "</head><body><h2>&#10003; {$title}</h2>"
            . "<p>{$body}</p>"
            . "</body></html>";
    }
}
