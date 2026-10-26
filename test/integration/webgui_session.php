<?php

declare(strict_types=1);

use OPNsense\Core\Backend;
use OPNsense\SSO\SessionEstablisher;
use OPNsense\SSO\SessionRegistry;
use OPNsense\SSO\StateDir;
use OPNsense\SSO\Test\Tree;

$root = dirname(__DIR__, 2);
$temporary = sys_get_temp_dir() . '/os-sso-webgui-' . bin2hex(random_bytes(8));
mkdir($temporary, 0700);
$source = file_get_contents($root . '/src/opnsense/mvc/app/library/OPNsense/SSO/StateDir.php');
eval('?>' . str_replace('/var/db/os-sso', $temporary . '/state', $source));
require $root . '/test/unit/lib/stubs.php';
spl_autoload_register(function (string $class) use ($root): void {
	$path = $root . '/src/opnsense/mvc/app/library/' . str_replace('\\', '/', $class) . '.php';
	if (str_starts_with($class, 'OPNsense\\') && is_file($path)) {
		require $path;
	}
});
ini_set('session.use_cookies', '0');
session_save_path($temporary);
$mode = $argv[1] ?? 'success';
$tree = Tree::build([['name' => 'alice', 'uid' => '2000', 'password' => '*']]);
$tree->system->addChild('webgui')->addChild('protocol', 'https');
if (str_starts_with($mode, 'depth-one')) {
	foreach (str_split('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,-') as $character) {
		if (!is_dir($temporary . '/' . $character)) {
			mkdir($temporary . '/' . $character, 0700);
		}
	}
	session_save_path('1;' . ($mode === 'depth-one-mode' ? '0600;' : '') . $temporary);
}
$result = [];
try {
	if ($mode !== 'inactive') {
		session_start();
	}
	$oldId = session_id();
	if ($mode === 'registry-failure') {
		$dir = StateDir::path('sessions');
		rmdir($dir);
		file_put_contents($dir, 'block session registry');
	}
	if ($mode === 'disabled') {
		$tree->system->user->addChild('disabled', '1');
	}
	try {
		(new SessionEstablisher())->establish('alice', 'kc', ['issuer' => 'https://idp.example', 'sub' => 'alice-sub', 'lifetime' => 600]);
		$result['accepted'] = true;
	} catch (RuntimeException $error) {
		$result['accepted'] = false;
		$result['error'] = $error->getMessage();
	}
	$result['username'] = $_SESSION['Username'] ?? '';
	$result['active'] = session_status() === PHP_SESSION_ACTIVE;
	$result['rotated'] = session_id() !== '' && session_id() !== $oldId;
	$result['registry'] = SessionRegistry::listActive();
	if ($result['accepted']) {
		$id = session_id();
		session_write_close();
		$result['persisted'] = str_contains((string)file_get_contents($temporary . (str_starts_with($mode, 'depth-one') ? '/' . $id[0] : '') . '/sess_' . $id), 'alice');
	}
} finally {
	if (session_status() === PHP_SESSION_ACTIVE) {
		session_destroy();
	}
	$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($temporary, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
	foreach ($files as $file) {
		$file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
	}
	rmdir($temporary);
}
echo json_encode($result, JSON_THROW_ON_ERROR) . "\n";
