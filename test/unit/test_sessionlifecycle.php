<?php

declare(strict_types=1);

use OPNsense\Core\Backend;
use OPNsense\SSO\SessionRegistry;
use OPNsense\SSO\StateDir;
use OPNsense\SSO\Test\Tree;

T::group('WebGUI: session establishment fails closed');
foreach (['success', 'depth-one', 'depth-one-mode', 'registry-failure', 'inactive', 'disabled'] as $mode) {
	$pipes = [];
	$process = proc_open([PHP_BINARY, dirname(__DIR__) . '/integration/webgui_session.php', $mode], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
	if (!is_resource($process)) {
		T::ko('session subprocess starts', $mode);
		continue;
	}
	fclose($pipes[0]);
	$output = stream_get_contents($pipes[1]);
	$error = stream_get_contents($pipes[2]);
	fclose($pipes[1]);
	fclose($pipes[2]);
	eq(0, proc_close($process), 'native PHP session fixture completes: ' . $mode . ' ' . $error);
	$result = json_decode($output, true);
	eq(in_array($mode, ['success', 'depth-one', 'depth-one-mode'], true), $result['accepted'] ?? null, 'only a recorded, usable session is accepted: ' . $mode);
	if (in_array($mode, ['success', 'depth-one', 'depth-one-mode'], true)) {
		eq('alice', $result['username'], 'the successful browser is authenticated');
		truthy($result['rotated'], 'the session ID changes');
		truthy($result['persisted'], 'the native PHP session persists');
		eq('2000', $result['registry'][0]['account_uid'], 'the recorded session pins the local UID');
	} else {
		eq('', $result['username'], 'failed establishment leaves no authenticated username');
		falsy($result['active'], 'failed establishment leaves no active PHP session');
		eq([], $result['registry'], 'failed establishment leaves no grant');
	}
}

if (!stateDirUsable()) {
	T::skip('account deletion and logout isolation', 'state directory unavailable');
	return;
}
SessionRegistry::destroyAll();
T::group('Grants: removed, renamed or replaced accounts lose access');
foreach (['removed', 'renamed', 'different-uid', 'different-uuid'] as $change) {
	$tree = Tree::build([['name' => 'alice', 'uid' => '2100']]);
	$tree->system->user->addAttribute('uuid', 'original');
	SessionRegistry::recordGrant(['kind' => SessionRegistry::VPN, 'username' => 'alice', 'vpn_username' => 'client-alice']);
	switch ($change) {
		case 'removed': unset($tree->system->user); break;
		case 'renamed': $tree->system->user->name = 'renamed'; break;
		case 'different-uid': $tree->system->user->uid = '2200'; break;
		case 'different-uuid': $tree->system->user['uuid'] = 'replacement'; break;
	}
	eq(1, SessionRegistry::sweep(), 'the old grant is revoked after ' . $change);
	eq([], SessionRegistry::listActive(), 'the old grant no longer survives');
}

T::group('Portal guests remain distinct from removed local accounts');
Tree::build([]);
SessionRegistry::recordGrant(['kind' => SessionRegistry::PORTAL, 'username' => 'guest', 'cp_session' => 'guest-session']);
eq(0, SessionRegistry::sweep(), 'a portal guest without a local account keeps valid access');
SessionRegistry::destroyAll();
Tree::build([['name' => 'alice', 'uid' => '2100', 'sso_subject' => 'kc|subject']]);
SessionRegistry::recordGrant(['kind' => SessionRegistry::PORTAL, 'username' => 'renamed-at-idp', 'provider' => 'kc', 'sub' => 'subject', 'cp_session' => 'bound-session']);
eq('2100', SessionRegistry::listActive()[0]['account_uid'], 'a portal account is found by durable subject despite its new IdP username');
Tree::build([]);
eq(1, SessionRegistry::sweep(), 'the bound portal grant ends when its local account is removed');

T::group('Older VPN grants without a UID are revoked when their required account disappears');
$dir = StateDir::path('sessions');
file_put_contents($dir . '/' . str_repeat('e', 64) . '.json', json_encode(['kind' => SessionRegistry::VPN, 'username' => 'old-user', 'vpn_cn' => 'old-user', 'expires_at' => time() + 3600]));
eq(1, SessionRegistry::sweep(), 'a legacy VPN grant cannot outlive account removal');

T::group('Logout stays within the provider, session and subject named by the validated message');
$grant = fn(string $provider, string $sub, string $sid) => SessionRegistry::recordGrant(['kind' => SessionRegistry::PORTAL, 'username' => 'guest', 'cp_session' => bin2hex(random_bytes(4)), 'issuer' => 'https://shared-idp.example', 'provider' => $provider, 'sub' => $sub, 'sid' => $sid]);
$grant('one', 'alice', 'session-a');
$grant('two', 'alice', 'session-a');
$grant('one', 'bob', 'session-a');
$grant('one', 'alice', '');
$grant('one', 'alice', 'session-b');
eq(1, SessionRegistry::destroyForSubject('https://shared-idp.example', 'alice', 'session-a', 'one'), 'both identifiers and the provider must match');
eq(4, count(SessionRegistry::listActive()), 'other providers, subjects and sessions remain');
eq(2, SessionRegistry::destroyForSubject('https://shared-idp.example', 'alice', '', 'one'), 'subject-only logout covers this provider only');
eq(0, SessionRegistry::destroyForSubject('https://shared-idp.example', 'alice', '', ''), 'an empty provider scope is refused');
SessionRegistry::destroyAll();
