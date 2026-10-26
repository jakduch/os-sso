<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\SSO\AccountStamps;
use OPNsense\SSO\ConfigLock;
use OPNsense\SSO\GroupMapper;
use OPNsense\SSO\GroupMembers;
use OPNsense\SSO\IdentityMapper;
use OPNsense\SSO\NormalizedIdentity;
use OPNsense\SSO\Scim\ScimUsers;
use OPNsense\SSO\SessionRegistry;
use OPNsense\SSO\SourceGate;
use OPNsense\SSO\StateDir;
use OPNsense\SSO\Test\Tree;
use OPNsense\SSO\VpnAuthorizer;

T::group('Source allowlists: malformed prefixes fail closed');
foreach (['10.20.30.40/', '10.20.30.40/typo', '10.20.30.40/24extra', '10.20.30.40/-0', '10.20.30.40/+0', '2001:db8::/bad', '10.20.30.40/0/1'] as $network) {
	falsy(SourceGate::isValidNetwork($network), 'invalid network: ' . $network);
	falsy(SourceGate::allows('203.0.113.99', [$network]), 'invalid network grants no source');
}
truthy(SourceGate::isValidList('192.0.2.1, 2001:db8::/64'), 'valid mixed-family source lists remain accepted');

T::group('PS256: shipped dependencies can sign and verify');
$pssKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
openssl_pkey_export($pssKey, $pssPem);
$pssToken = JWT::encode(['sub' => 'alice', 'exp' => time() + 60], $pssPem, 'PS256');
eq('alice', JWT::decode($pssToken, new Key(openssl_pkey_get_details($pssKey)['key'], 'PS256'))->sub, 'a real PSS signature verifies with installed dependencies');

if (!stateDirUsable()) {
	T::skip('state-dependent safety regressions', 'state directory unavailable');
	return;
}

T::group('Core transaction locks are released after exceptions');
$locksBefore = Config::$locks;
$unlocksBefore = Config::$unlocks;
throws(fn() => ConfigLock::with(fn() => throw new RuntimeException('fixture failure')), 'fixture failure', 'transaction failures propagate');
eq($locksBefore + 1, Config::$locks, 'the core lock is acquired');
eq($unlocksBefore + 1, Config::$unlocks, 'the core lock is released on failure');

T::group('SCIM decisions override an earlier automatic deprovisioning');
$root = Tree::build([[
	'name' => 'alice', 'uid' => '2100', 'password' => '*', 'scrambled_password' => '1',
	'sso_owned' => '1', 'sso_subject' => 'kc|alice-sub', 'scim_provider' => 'kc',
	'disabled' => '1', 'sso_deprovisioned' => '1',
]]);
$scim = new ScimUsers('kc', 'https://firewall.example/api/sso/scim');
$scim->patch('2100', [['op' => 'replace', 'path' => 'active', 'value' => false]]);
eq('', AccountStamps::value(Tree::user($root, 'alice'), 'sso_deprovisioned'), 'SCIM removes the automatic-revival permission even when already disabled');
$identity = new NormalizedIdentity('kc');
$identity->username = 'alice';
$identity->subject = 'alice-sub';
throws(fn() => (new IdentityMapper())->resolve($identity, false, []), 'disabled', 'an otherwise valid login cannot undo explicit SCIM deactivation');
falsy($scim->get('2100')['active'], 'the account stays disabled');

T::group('SCIM optimistic concurrency is enforced inside each mutation');
$oldVersion = $scim->get('2100')['meta']['version'];
$scim->patch('2100', [['op' => 'replace', 'path' => 'displayName', 'value' => 'new directory value']]);
foreach ([
	fn() => $scim->patch('2100', [['op' => 'replace', 'path' => 'displayName', 'value' => 'stale value']], $oldVersion),
	fn() => $scim->replace('2100', ['userName' => 'alice', 'displayName' => 'stale value'], $oldVersion),
	fn() => $scim->deactivate('2100', $oldVersion),
] as $staleWrite) {
	try {
		$staleWrite();
		T::ko('stale conditional write', 'accepted');
	} catch (\OPNsense\SSO\Scim\ScimError $error) {
		eq(412, $error->status(), 'stale write returns Precondition Failed');
	}
}
eq('new directory value', $scim->get('2100')['displayName'], 'the competing writer is not overwritten');
$scim->patch('2100', [['op' => 'replace', 'value' => ['userName' => 'alice-renamed']]]);
eq('alice-renamed', $scim->get('2100')['userName'], 'pathless PATCH updates userName too');

T::group('Failed revocations remain recorded and are retried');
SessionRegistry::destroyAll();
SessionRegistry::recordGrant(['kind' => SessionRegistry::VPN, 'username' => 'alice', 'vpn_cn' => 'alice']);
Backend::$responses['sso vpn_kill'] = '{"status":"error","killed":0}';
eq(0, SessionRegistry::destroyAll(), 'a failed VPN kill is not reported successful');
eq(1, count(SessionRegistry::listActive()), 'the failed grant remains available for retry');
unset(Backend::$responses['sso vpn_kill']);
eq(1, SessionRegistry::sweep(), 'the sweeper retries pending revocation before the grant expires');
SessionRegistry::recordGrant(['kind' => SessionRegistry::PORTAL, 'username' => 'guest', 'cp_session' => 'portal-fixture']);
Backend::$responses['captiveportal disconnect'] = 'service unavailable';
eq(0, SessionRegistry::destroyAll(), 'an unacknowledged portal disconnect is retained');
Backend::$responses['captiveportal disconnect'] = '{"terminateCause":"UNKNOWN"}';
eq(1, SessionRegistry::destroyAll(), 'core confirms a portal session that is already absent');
Backend::$responses = [];

T::group('VPN grant persistence precedes the positive verdict');
$observedGrant = false;
Backend::$observer = function (string $action) use (&$observedGrant): void {
	if ($action === 'sso vpn_verdict') {
		$observedGrant = count(SessionRegistry::listActive()) === 1;
	}
};
eq('alice', VpnAuthorizer::authorize(str_repeat('a', 32), 'alice', '192.0.2.1', ['issuer' => 'https://idp.example', 'sub' => 'alice-sub']), 'a revocable tunnel is authorized');
Backend::$observer = null;
truthy($observedGrant, 'the registry entry already exists when OpenVPN receives approval');
SessionRegistry::destroyAll();
$sessions = StateDir::path('sessions');
rmdir($sessions);
file_put_contents($sessions, 'block the session store, leave the config lock usable');
try {
	Backend::$calls = [];
	throws(fn() => VpnAuthorizer::authorize(str_repeat('b', 32), 'alice', '192.0.2.1'), 'could not be recorded', 'an unusable registry prevents approval');
	eq(['sso vpn_inspect'], array_column(Backend::$calls, 0), 'no positive verdict is sent when persistence fails');
} finally {
	unlink($sessions);
	mkdir($sessions, 0700);
}

T::group('Last-admin protection retains pending group revocations');
$root = Tree::build([
	['name' => 'alice', 'uid' => '2100', 'sso_owned' => '1', 'sso_groups' => 'admins'],
	['name' => 'root', 'uid' => '0', 'scope' => 'system'],
], [['name' => 'admins', 'gid' => '1999', 'priv' => 'page-all', 'member' => '2100']]);
$mapper = new GroupMapper([], true);
$mapper->sync(Tree::user($root, 'alice'), $identity, []);
truthy(GroupMembers::contains(Tree::group($root, 'admins'), '2100'), 'the last enabled administrator is retained');
eq('admins', AccountStamps::value(Tree::user($root, 'alice'), 'sso_groups'), 'the deferred removal remains tracked');
GroupMembers::set(Tree::group($root, 'admins'), ['2100', '0']);
$mapper->sync(Tree::user($root, 'alice'), $identity, []);
falsy(GroupMembers::contains(Tree::group($root, 'admins'), '2100'), 'the obsolete membership is removed after another administrator is available');
truthy(GroupMembers::contains(Tree::group($root, 'admins'), '0'), 'the local administrator remains');
