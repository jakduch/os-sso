<?php

declare(strict_types=1);

use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\SSO\Deprovisioner;
use OPNsense\SSO\NormalizedIdentity;
use OPNsense\SSO\Scim\ScimUsers;
use OPNsense\SSO\SessionRegistry;
use OPNsense\SSO\Test\Tree;
use OPNsense\SSO\VpnAuthorizer;

if (!stateDirUsable()) {
	T::skip('network grant revocation regressions', 'state directory unavailable');
	return;
}
SessionRegistry::destroyAll();
T::group('VPN: final authorization rechecks the local account');
foreach ([
	'disabled' => [['name' => 'alice', 'uid' => '2100', 'disabled' => '1']],
	'expired' => [['name' => 'alice', 'uid' => '2100', 'expires' => date('m/d/Y', strtotime('-2 days'))]],
	'removed' => [],
] as $reason => $users) {
	Tree::build($users);
	Backend::$calls = [];
	throws(fn() => VpnAuthorizer::authorize(str_repeat('a', 32), 'alice', '192.0.2.1'), '', 'an account ' . $reason . ' after mapping cannot get VPN approval');
	eq([], Backend::$calls, 'no privileged VPN operation occurs for the unusable account');
	SessionRegistry::destroyAll();
}
Tree::build([['name' => 'alice', 'uid' => '2100']]);
$lockedDuringVerdict = false;
Backend::$observer = function (string $action) use (&$lockedDuringVerdict): void {
	if ($action === 'sso vpn_verdict') {
		$lockedDuringVerdict = Config::$locks === Config::$unlocks + 1;
	}
};
try {
	eq('alice', VpnAuthorizer::authorize(str_repeat('b', 32), 'alice', '192.0.2.1'), 'an enabled account still receives approval');
	truthy($lockedDuringVerdict, 'account validation, grant persistence and verdict share the core lock');
} finally {
	Backend::$observer = null;
	SessionRegistry::destroyAll();
}

T::group('SCIM: revocation follows UID rather than an IdP username alias');
foreach (['scim', 'required-group-refusal'] as $reason) {
	Tree::build([['name' => 'alice', 'uid' => '2100', 'password' => '*', 'scrambled_password' => '1', 'sso_owned' => '1', 'sso_subject' => 'kc|alice-sub', 'scim_provider' => 'kc']]);
	SessionRegistry::recordGrant(['kind' => SessionRegistry::PORTAL, 'username' => 'alice-at-idp', 'provider' => 'kc', 'sub' => 'alice-sub', 'cp_session' => 'alias-session']);
	SessionRegistry::recordGrant(['kind' => SessionRegistry::PORTAL, 'username' => 'unrelated-guest', 'cp_session' => 'unrelated-session']);
	$alias = array_values(array_filter(SessionRegistry::listActive(), fn(array $entry): bool => $entry['cp_session'] === 'alias-session'))[0];
	eq('2100', $alias['account_uid'], 'the aliased grant belongs to the local account');
	Backend::$calls = [];
	if ($reason === 'scim') {
		(new ScimUsers('kc', 'https://firewall.example/scim'))->patch('2100', [['op' => 'replace', 'path' => 'active', 'value' => false]]);
	} else {
		$identity = new NormalizedIdentity('kc');
		$identity->subject = 'alice-sub';
		$identity->username = 'alice-at-idp';
		truthy(Deprovisioner::disableFor($identity), 'a required-group refusal disables the account');
	}
	eq(1, count(SessionRegistry::listActive()), 'the aliased grant is revoked immediately: ' . $reason);
	eq('unrelated-guest', SessionRegistry::listActive()[0]['username'] ?? '', 'another portal guest is preserved');
	truthy(in_array(['captiveportal disconnect', ['alias-session', 'os-sso revocation']], Backend::$calls, true), 'the actual portal session was disconnected');
	SessionRegistry::destroyAll();
}

T::group('Account revocation preserves another UID even when display names collide');
$root = Tree::build([['name' => 'alice', 'uid' => '2100']]);
SessionRegistry::recordGrant(['kind' => SessionRegistry::PORTAL, 'username' => 'alice', 'cp_session' => 'old-account-session']);
$root->system->user->uid = '2200';
eq(0, SessionRegistry::destroyForAccount($root->system->user), 'another account with the same name is not the recorded UID');
eq(1, SessionRegistry::sweep(), 'the old, replaced account is independently revoked by the sweep');

T::group('VPN: an exception while writing a verdict starts revocation');
Tree::build([['name' => 'alice', 'uid' => '2100']]);
Backend::$responses['sso vpn_kill'] = '{"status":"error","killed":0}';
Backend::$observer = function (string $action): void {
	if ($action === 'sso vpn_verdict') {
		throw new RuntimeException('configd transport failure');
	}
};
try {
	throws(fn() => VpnAuthorizer::authorize(str_repeat('c', 32), 'alice', '192.0.2.1'), 'configd transport failure', 'the original authorization failure propagates');
	$pending = SessionRegistry::listActive();
	eq(1, count($pending), 'an unacknowledged disconnect leaves a retryable grant');
	truthy($pending[0]['revocation_pending'] ?? false, 'revocation starts immediately rather than at original expiry');
} finally {
	Backend::$observer = null;
	unset(Backend::$responses['sso vpn_kill']);
	SessionRegistry::destroyAll();
}

T::group('Captive portal: authorization replies must identify a revocable session');
Tree::build([]);
\OPNsense\CaptivePortal\CaptivePortal::useZone('1', 'kc');
$identity = new NormalizedIdentity('kc');
$identity->username = 'guest';
foreach ([
	['clientState' => 'AUTHORIZED'],
	['clientState' => 'AUTHORIZED', 'sessionId' => ''],
	['clientState' => 'AUTHORIZED', 'sessionId' => ['unexpected']],
	['clientState' => 'FAILED', 'sessionId' => 'unconfirmed'],
	['sessionId' => 'unconfirmed'],
] as $reply) {
	Backend::$responses['captiveportal allow'] = json_encode($reply);
	throws(fn() => \OPNsense\SSO\CaptivePortalAuthorizer::authorize('1', 'kc', $identity, '192.0.2.1'), 'authorization failed', 'a partial or contradictory reply is refused');
}
unset(Backend::$responses['captiveportal allow']);
throws(fn() => \OPNsense\SSO\CaptivePortalAuthorizer::recordGrant(['username' => 'guest', 'zone' => '1', 'session' => ['clientState' => 'AUTHORIZED']], ['provider' => 'kc']), 'no revocable session ID', 'an empty portal handle is never added to the registry');
eq([], SessionRegistry::listActive(), 'failed portal replies leave no unrevocable record');

T::group('Captive portal: a contradictory reply is rolled back and failures are reported');
Backend::$calls = [];
Backend::$responses['captiveportal allow'] = '{"clientState":"FAILED","sessionId":"uncertain-session"}';
throws(fn() => \OPNsense\SSO\CaptivePortalAuthorizer::authorize('1', 'kc', $identity, '192.0.2.1'), 'authorization failed', 'a session from an uncertain reply is refused');
truthy(in_array(['captiveportal disconnect', ['uncertain-session', 'os-sso revocation']], Backend::$calls, true), 'the identified session is given back before refusing the reply');
Backend::$responses['captiveportal disconnect'] = 'service unavailable';
try {
	throws(fn() => \OPNsense\SSO\CaptivePortalAuthorizer::authorize('1', 'kc', $identity, '192.0.2.1'), 'rollback was not acknowledged', 'a failed rollback is never reported as a successful disconnect');
	eq(1, count(SessionRegistry::listActive()), 'the uncertain session remains recorded after a failed rollback');
	truthy(SessionRegistry::listActive()[0]['revocation_pending'] ?? false, 'the failed rollback is marked for retry');
} finally {
	unset(Backend::$responses['captiveportal allow'], Backend::$responses['captiveportal disconnect']);
}

eq(1, SessionRegistry::sweep(), 'the sweeper retries a failed portal rollback after the backend recovers');
eq([], SessionRegistry::listActive(), 'an acknowledged retry retires the uncertain grant');
