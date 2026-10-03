<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

function sso_configure()
{
	return [
		'bootup' => ['sso_openvpn_bootup'],
		'crl' => ['sso_openvpn_sync:0'],
	];
}


function sso_run(): array
{
	return ['openvpn_instance_config' => 'sso_openvpn_instance_config'];
}


function sso_openvpn_instance_config(string $uuid): array
{
	try {
		return \OPNsense\SSO\OpenVpnIntegration::instanceOptions($uuid);
	} catch (\Throwable $exception) {
		/*
		 * plugins_run() catches Error; convert every failure into an exception so
		 * OpenVPN generation aborts instead of silently losing authentication.
		 */
		throw new \RuntimeException(
			'os-sso OpenVPN configuration failed: ' . $exception->getMessage(),
			0,
			$exception,
		);
	}
}


function sso_openvpn_sync(): void
{
	try {
		\OPNsense\SSO\OpenVpnIntegration::synchronize();
	} catch (\Throwable $exception) {
		/*
		 * Never abort core's CRL hook. The guard manifest is written before the
		 * config save, so the supervisor stops any selected instance whose saved
		 * or generated configuration cannot be proven safe.
		 */
		syslog(LOG_ERR, 'os-sso: OpenVPN integration failed: ' . $exception->getMessage());
	}
}


function sso_openvpn_bootup(): void
{
	sso_openvpn_sync();
	mwexecf('/usr/local/etc/rc.d/os-sso-vpn-guard onestart');
}


function sso_services()
{
	return [[
		'description' => gettext('os-sso OpenVPN authentication guard'),
		'pidfile' => '/var/run/os-sso-vpn-guard.pid',
		'configd' => [
			'start' => ['sso guard_start'],
			'stop' => ['sso guard_stop'],
			'restart' => ['sso guard_restart'],
		],
		'name' => 'sso_vpn_guard',
	]];
}


function sso_xmlrpc_sync(): array
{
	return [[
		'description' => gettext('Single Sign-On'),
		'help' => gettext(
			'Synchronize os-sso OpenVPN web-auth profiles to the other HA host. '
			. 'Enable Authentication Servers, OpenVPN, Users and Groups, and Certificates separately when used.'
		),
		'section' => 'OPNsense.SSO',
		'id' => 'sso',
		'services' => ['sso_vpn_guard', 'openvpn'],
	]];
}


function sso_syslog()
{
	return ['os-sso-vpn-guard' => ['facility' => ['os-sso-vpn-guard']]];
}
