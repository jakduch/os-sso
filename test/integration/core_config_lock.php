<?php

declare(strict_types=1);

namespace OPNsense\Core {
	class Singleton
	{
		public static ?Config $fixture = null;

		public static function getInstance(): Config
		{
			return self::$fixture;
		}
	}
}

namespace {
	$coreSource = $argv[1] ?? '';
	if (!is_file($coreSource)) {
		fwrite(STDERR, "Pass the reviewed OPNsense Core/Config.php source path.\n");
		exit(1);
	}
	require $coreSource;

	class FixtureConfig extends \OPNsense\Core\Config
	{
		public function getRevisionContext(): array
		{
			return ['username' => 'test', 'description' => 'isolated transaction', 'time' => time()];
		}

		public function getBackups($fetchRevisionInfo = false): array
		{
			return [];
		}

		public function forceReload(): void
		{
			(new \ReflectionMethod(\OPNsense\Core\Config::class, 'load'))->invoke($this);
		}
	}

	function fixtureConfig(string $path): FixtureConfig
	{
		$config = (new \ReflectionClass(FixtureConfig::class))->newInstanceWithoutConstructor();
		(new \ReflectionProperty(\OPNsense\Core\Config::class, 'config_file'))->setValue($config, $path);
		$config->forceReload();
		return $config;
	}

	if (($argv[2] ?? '') === 'disable-user') {
		$config = fixtureConfig($argv[3]);
		$config->lock();
		$config->object()->system->user[0]->disabled = '1';
		$config->save(null, false);
		$config->unlock();
		exit(0);
	}

	if (($argv[2] ?? '') === 'core-writer') {
		$config = fixtureConfig($argv[3]);
		touch($argv[4]);
		$config->lock();
		$config->object()->system->hostname = 'administrator-change';
		$user = $config->object()->system->addChild('user');
		$user->addChild('name', 'bob');
		$user->addChild('uid', (string)$config->object()->system->nextuid);
		$config->object()->system->nextuid = (string)((int)$config->object()->system->nextuid + 1);
		$config->save(null, false);
		$config->unlock();
		exit(0);
	}

	$root = dirname(__DIR__, 2);
	$temporary = sys_get_temp_dir() . '/os-sso-core-lock-' . getmypid();
	mkdir($temporary, 0700);
	$source = file_get_contents($root . '/src/opnsense/mvc/app/library/OPNsense/SSO/StateDir.php');
	eval('?>' . str_replace('/var/db/os-sso', $temporary . '/state', $source));
	require $root . '/src/opnsense/mvc/app/library/OPNsense/SSO/ConfigLock.php';
	$path = $temporary . '/config.xml';
	$signal = $temporary . '/writer-started';
	file_put_contents($path, '<opnsense><system><hostname>before</hostname><nextuid>2000</nextuid></system></opnsense>');
	$config = fixtureConfig($path);
	\OPNsense\Core\Singleton::$fixture = $config;
	$process = null;
	$pipes = [];
	try {
		\OPNsense\SSO\ConfigLock::with(function () use ($config, $path, $signal, $coreSource, &$process, &$pipes): void {
			$user = $config->object()->system->addChild('user');
			$user->addChild('name', 'alice');
			$user->addChild('uid', (string)$config->object()->system->nextuid);
			$config->object()->system->nextuid = '2001';
			$process = proc_open([PHP_BINARY, __FILE__, $coreSource, 'core-writer', $path, $signal], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
			if (!is_resource($process)) {
				throw new RuntimeException('cannot start concurrent core writer');
			}
			$deadline = microtime(true) + 5;
			while (!is_file($signal) && microtime(true) < $deadline) {
				usleep(10000);
				clearstatcache(true, $signal);
			}
			if (!is_file($signal)) {
				throw new RuntimeException('concurrent writer did not start');
			}
			usleep(100000);
			$config->save(null, false);
		});
		fclose($pipes[0]);
		$output = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		$status = proc_close($process);
		$process = null;
		$result = simplexml_load_file($path);
		$users = [];
		foreach ($result->system->user as $user) {
			$users[(string)$user->name] = (string)$user->uid;
		}
		if ($status !== 0 || $users !== ['alice' => '2000', 'bob' => '2001'] || (string)$result->system->hostname !== 'administrator-change') {
			throw new RuntimeException('core transaction was lost or UIDs collided: ' . json_encode($users) . ' ' . $output);
		}
		// The mapper may have read an enabled account just before another worker
		// disables it. Establishment must reload and refuse this stale decision.
		$process = proc_open([PHP_BINARY, __FILE__, $coreSource, 'disable-user', $path], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
		if (!is_resource($process)) {
			throw new RuntimeException('cannot start concurrent account deactivation');
		}
		fclose($pipes[0]);
		$output = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		if (proc_close($process) !== 0) {
			throw new RuntimeException('account deactivation failed: ' . $output);
		}
		$process = null;
		if ((string)$config->object()->system->user[0]->disabled === '1') {
			throw new RuntimeException('the stale account fixture unexpectedly refreshed itself');
		}
		spl_autoload_register(function (string $class) use ($root): void {
			$file = $root . '/src/opnsense/mvc/app/library/' . str_replace('\\', '/', $class) . '.php';
			if (str_starts_with($class, 'OPNsense\\') && is_file($file)) {
				require $file;
			}
		});
		ini_set('session.use_cookies', '0');
		session_save_path($temporary);
		session_start();
		$refused = false;
		try {
			(new \OPNsense\SSO\SessionEstablisher())->establish('alice', 'fixture');
		} catch (RuntimeException $error) {
			$refused = str_contains($error->getMessage(), 'disabled or expired');
		}
		if (!$refused || isset($_SESSION['Username']) || session_status() === PHP_SESSION_ACTIVE) {
			throw new RuntimeException('a stale pre-deactivation decision established a browser session');
		}
		// The VPN callback must also reload rather than trust the mapper's cache.
		$config->object()->system->user[0]->disabled = '0';
		$vpnRefused = false;
		try {
			\OPNsense\SSO\VpnAuthorizer::authorize(str_repeat('a', 32), 'alice', '192.0.2.1');
		} catch (RuntimeException $error) {
			$vpnRefused = str_contains($error->getMessage(), 'disabled or expired');
		}
		if (!$vpnRefused) {
			throw new RuntimeException('a stale account decision reached the privileged VPN backend');
		}
		echo "Concurrent SSO/core transactions preserve both users, unique UIDs and the administrator change.\n";
		echo "Session establishment rejects an account deactivated after the earlier provisioning decision.\n";
		echo "VPN authorization also reloads and refuses that deactivated account before any privileged verdict.\n";
	} finally {
		if (is_resource($process)) {
			proc_terminate($process);
			proc_close($process);
		}
		$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($temporary, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
		foreach ($files as $file) {
			$file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
		}
		rmdir($temporary);
	}
}
