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
		echo "Concurrent SSO/core transactions preserve both users, unique UIDs and the administrator change.\n";
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
