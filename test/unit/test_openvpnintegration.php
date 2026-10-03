<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

use OPNsense\Core\Config;
use OPNsense\SSO\OpenVpnIntegration;

const VPN_UUID_A = '11111111-1111-4111-8111-111111111111';
const VPN_UUID_B = '22222222-2222-4222-8222-222222222222';


/**
 * @param array<int, array<string, string>> $profiles
 * @param array<int, array<string, string>> $instances
 */
function vpnTree(array $profiles, array $instances): SimpleXMLElement
{
	$xml = '<opnsense><OPNsense><SSO><settings><vpn><profiles/></vpn></settings></SSO>'
		. '<OpenVPN><Instances/></OpenVPN></OPNsense></opnsense>';
	$root = new SimpleXMLElement($xml);
	foreach ($profiles as $profile) {
		$node = $root->OPNsense->SSO->settings->vpn->profiles->addChild('profile');
		foreach ($profile as $key => $value) {
			$node->addChild($key, htmlspecialchars($value, ENT_XML1));
		}
	}
	foreach ($instances as $instance) {
		$node = $root->OPNsense->OpenVPN->Instances->addChild('Instance');
		$node->addAttribute('uuid', $instance['uuid']);
		foreach (array_diff_key($instance, ['uuid' => true]) as $key => $value) {
			$node->addChild($key, htmlspecialchars($value, ENT_XML1));
		}
	}

	return $root;
}


function vpnProfile(string $name, string $uuid = VPN_UUID_A, string $enabled = '1'): array
{
	return ['enabled' => $enabled, 'name' => $name, 'openvpn_instance' => $uuid];
}


function vpnInstance(
	string $uuid,
	string $flags = 'float',
	string $authmode = '',
	string $enabled = '1',
	string $role = 'server',
): array {
	return [
		'uuid' => $uuid,
		'enabled' => $enabled,
		'role' => $role,
		'authmode' => $authmode,
		'various_flags' => $flags,
	];
}


T::group('OpenVpnIntegration: generated options');

$tree = vpnTree([vpnProfile('staff')], [vpnInstance(VPN_UUID_A)]);
$expectedOptions = [
	'auth-user-pass-verify' => '"' . OpenVpnIntegration::HOOK . ' staff" via-file',
	'auth-user-pass-optional' => null,
];
eq(
	$expectedOptions,
	OpenVpnIntegration::options($tree, VPN_UUID_A),
	'it returns the two generated directives',
);
Config::useTree($tree);
require_once dirname(__DIR__, 2) . '/src/etc/inc/plugins.inc.d/sso.inc';
eq($expectedOptions, sso_openvpn_instance_config(VPN_UUID_A), 'the registered plugin callback returns those options');
eq('float', (string)$tree->OPNsense->OpenVPN->Instances->Instance->various_flags, 'it never modifies config.xml');
eq([], OpenVpnIntegration::options($tree, VPN_UUID_B), 'an unrelated instance receives no options');

T::group('OpenVpnIntegration: legacy config migration');

if (!stateDirUsable()) {
	T::skip('the migration cases', 'needs a writable /var/db/os-sso for the config lock');
} else {
	$legacyHook = 'auth-user-pass-verify "' . OpenVpnIntegration::HOOK . ' staff" via-file';
	$tree = vpnTree(
		[vpnProfile('staff')],
		[vpnInstance(VPN_UUID_A, 'float,' . $legacyHook . ',auth-user-pass-optional')],
	);
	throws(
		fn() => OpenVpnIntegration::options($tree, VPN_UUID_A),
		'legacy os-sso authentication directive',
		'generation aborts until the one-time cleanup succeeds',
	);
	Config::useTree($tree);
	$manifest = sys_get_temp_dir() . '/os-sso-openvpn-' . bin2hex(random_bytes(8)) . '.json';
	try {
		$result = OpenVpnIntegration::synchronize($manifest);
		truthy($result['changed'], 'it reports removal of directives written by an older release');
		eq(1, Config::$saves, 'it persists the one-time cleanup');
		eq('float', (string)$tree->OPNsense->OpenVPN->Instances->Instance->various_flags, 'native flags survive cleanup');
		eq('staff', $result['instances'][VPN_UUID_A]['profile'], 'the guard manifest still names the profile');
	} finally {
		@unlink($manifest);
	}
}

T::group('OpenVpnIntegration: multiple instances');

$tree = vpnTree(
	[vpnProfile('staff', VPN_UUID_A . ',' . VPN_UUID_B)],
	[vpnInstance(VPN_UUID_A), vpnInstance(VPN_UUID_B, 'client-to-client')],
);
eq(
	OpenVpnIntegration::options($tree, VPN_UUID_A),
	OpenVpnIntegration::options($tree, VPN_UUID_B),
	'both selected instances receive the shared profile options',
);

T::group('OpenVpnIntegration: moving and disabling profiles');

$tree = vpnTree(
	[vpnProfile('staff', VPN_UUID_B)],
	[vpnInstance(VPN_UUID_A), vpnInstance(VPN_UUID_B, 'client-to-client')],
);
eq([], OpenVpnIntegration::options($tree, VPN_UUID_A), 'moving a profile removes options from its old instance');
eq(
	[
		'auth-user-pass-verify' => '"' . OpenVpnIntegration::HOOK . ' staff" via-file',
		'auth-user-pass-optional' => null,
	],
	OpenVpnIntegration::options($tree, VPN_UUID_B),
	'and adds options to the new instance',
);

$tree = vpnTree([vpnProfile('staff', VPN_UUID_A, '0')], [vpnInstance(VPN_UUID_A)]);
eq([], OpenVpnIntegration::options($tree, VPN_UUID_A), 'disabling a profile removes the generated options');

T::group('OpenVpnIntegration: refusing ambiguous or unsafe ownership');

$tree = vpnTree(
	[vpnProfile('staff'), vpnProfile('contractors')],
	[vpnInstance(VPN_UUID_A)],
);
throws(
	fn() => OpenVpnIntegration::options($tree, VPN_UUID_A),
	'selected by both',
	'one OpenVPN instance cannot belong to two enabled profiles',
);

$tree = vpnTree(
	[
		vpnProfile('staff', VPN_UUID_A . ',' . VPN_UUID_B),
		vpnProfile('contractors', VPN_UUID_B),
	],
	[vpnInstance(VPN_UUID_A), vpnInstance(VPN_UUID_B)],
);
throws(
	fn() => OpenVpnIntegration::options($tree, VPN_UUID_A),
	'selected by both',
	'an instance in a multi-selection cannot belong to a second enabled profile',
);

$tree = vpnTree([vpnProfile('staff')], [vpnInstance(VPN_UUID_A, 'float', 'Local Database')]);
throws(
	fn() => OpenVpnIntegration::options($tree, VPN_UUID_A),
	'already has Authentication configured',
	'core password authentication cannot run alongside web-auth',
);
Config::useTree($tree);
throws(
	fn() => sso_openvpn_instance_config(VPN_UUID_A),
	'os-sso OpenVPN configuration failed',
	'the plugin callback aborts generation instead of losing authentication',
);

$tree = vpnTree([vpnProfile('staff')], [vpnInstance(VPN_UUID_A, 'float', '', '0')]);
throws(
	fn() => OpenVpnIntegration::options($tree, VPN_UUID_A),
	'is disabled',
	'a disabled instance cannot be managed',
);

$tree = vpnTree([vpnProfile('staff')], [vpnInstance(VPN_UUID_A, 'float', '', '1', 'client')]);
throws(
	fn() => OpenVpnIntegration::options($tree, VPN_UUID_A),
	'is not a server',
	'an OpenVPN client instance cannot be managed',
);

$tree = vpnTree([vpnProfile('staff', VPN_UUID_B)], [vpnInstance(VPN_UUID_A)]);
throws(
	fn() => OpenVpnIntegration::options($tree, VPN_UUID_A),
	'does not exist',
	'a missing selected instance is refused',
);

T::group('OpenVpnIntegration: backwards compatible manual profiles');

$tree = vpnTree([vpnProfile('legacy', '')], [vpnInstance(VPN_UUID_A, 'float')]);
eq([], OpenVpnIntegration::options($tree, VPN_UUID_A), 'a legacy profile without an instance adds no options');
