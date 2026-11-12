<?php

declare(strict_types=1);

namespace OPNsense\SSO;

// Keep filesystem failure injection in its own process, away from other suites.
function file_put_contents(string $file, string $data): int|false
{
	return match ($GLOBALS['requestObjectFailure']) {
		'write' => false,
		'short-write' => \file_put_contents($file, substr($data, 0, 1)),
		default => \file_put_contents($file, $data),
	};
}


function chmod(string $file, int $mode): bool
{
	return $GLOBALS['requestObjectFailure'] !== 'chmod' && \chmod($file, $mode);
}


function rename(string $from, string $to): bool
{
	return $GLOBALS['requestObjectFailure'] !== 'rename' && \rename($from, $to);
}

$root = dirname(__DIR__, 2);
$temporary = sys_get_temp_dir() . '/os-sso-request-' . bin2hex(random_bytes(8));
mkdir($temporary, 0700);
$source = \file_get_contents($root . '/src/opnsense/mvc/app/library/OPNsense/SSO/StateDir.php');
eval('?>' . str_replace('/var/db/os-sso', $temporary . '/state', $source));
require $root . '/src/opnsense/mvc/app/library/OPNsense/SSO/RequestObjectStore.php';
$GLOBALS['requestObjectFailure'] = $argv[1] ?? '';
$accepted = false;
try {
	RequestObjectStore::put('header.payload.signature');
	$accepted = true;
} catch (\RuntimeException $error) {
	// Expected failures must not return an id or leave a partially stored object.
}
$directory = StateDir::path('request');
$remaining = array_values(array_diff(scandir($directory), ['.', '..']));
echo json_encode(['accepted' => $accepted, 'remaining' => $remaining]);
foreach ($remaining as $file) {
	unlink($directory . '/' . $file);
}
rmdir($directory);
rmdir($temporary . '/state');
rmdir($temporary);
