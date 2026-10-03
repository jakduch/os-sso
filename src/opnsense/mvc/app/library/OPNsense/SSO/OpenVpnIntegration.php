<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 Maxime Wewer
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\SSO;

use OPNsense\Core\Config;
use RuntimeException;
use SimpleXMLElement;

/**
 * Supplies the OpenVPN directives that enable deferred web authentication.
 */
final class OpenVpnIntegration
{
	public const MANIFEST = '/usr/local/etc/sso/openvpn-instances.json';
	public const HOOK = '/usr/local/opnsense/scripts/OPNsense/SSO/auth-user-pass-verify.sh';

	private const OPTIONAL_DIRECTIVE = 'auth-user-pass-optional';


	/**
	 * Validate configured instances and write the guard manifest under the same lock.
	 *
	 * @return array{changed: bool, instances: array<string, array<string, string>>}
	 */
	public static function synchronize(string $manifestPath = self::MANIFEST): array
	{
		return ConfigLock::with(function () use ($manifestPath): array {
			$config = Config::getInstance();
			$root = $config->object();
			/*
			 * Publish the desired instances before validating their OpenVPN side. If
			 * validation fails (for example, core Authentication was enabled later),
			 * the guard still knows which running instance must be stopped.
			 */
			$desired = self::desiredInstances($root);
			$instances = self::openVpnInstances($root);
			self::writeManifest(self::manifest($desired), $manifestPath);
			$changed = self::removeLegacyFlags($instances);
			if ($changed && $config->save() === false) {
				throw new RuntimeException('OpenVPN integration could not remove legacy directives from config.xml');
			}
			self::validate($desired, $instances);

			return ['changed' => $changed, 'instances' => self::manifest($desired)];
		});
	}


	/**
	 * Return additional generated options for one OpenVPN instance.
	 *
	 * @return array<string, string|null>
	 */
	public static function instanceOptions(string $uuid): array
	{
		return self::options(Config::getInstance()->object(), $uuid);
	}


	/**
	 * Public test seam for instanceOptions().
	 *
	 * @return array<string, string|null>
	 */
	public static function options(SimpleXMLElement $config, string $uuid): array
	{
		$desired = self::desiredInstances($config);
		$instances = self::openVpnInstances($config);
		self::validate($desired, $instances);

		if (!isset($desired[$uuid])) {
			return [];
		}

		return [
			'auth-user-pass-verify' => self::hookValue($desired[$uuid]),
			self::OPTIONAL_DIRECTIVE => null,
		];
	}


	/**
	 * @param array<string, string> $desired
	 * @param array<string, SimpleXMLElement> $instances
	 */
	private static function validate(array $desired, array $instances): void
	{
		foreach ($desired as $uuid => $profile) {
			if (!isset($instances[$uuid])) {
				throw new RuntimeException("OpenVPN instance '{$uuid}' selected by profile '{$profile}' does not exist");
			}
			$instance = $instances[$uuid];
			if ((string)($instance->enabled ?? '') !== '1') {
				throw new RuntimeException("OpenVPN instance '{$uuid}' selected by profile '{$profile}' is disabled");
			}
			if ((string)($instance->role ?? '') !== 'server') {
				throw new RuntimeException("OpenVPN instance '{$uuid}' selected by profile '{$profile}' is not a server");
			}
			if (trim((string)($instance->authmode ?? '')) !== '') {
				throw new RuntimeException(
					"OpenVPN instance '{$uuid}' already has Authentication configured; clear it before enabling profile '{$profile}'"
				);
			}
			foreach (self::flags($instance) as $flag) {
				if (self::isOwnedHook($flag)) {
					throw new RuntimeException(
						"OpenVPN instance '{$uuid}' still contains a legacy os-sso authentication directive"
					);
				}
			}
		}
	}


	private static function hookValue(string $profile): string
	{
		return sprintf('"%s %s" via-file', self::HOOK, $profile);
	}


	private static function hookDirective(string $profile): string
	{
		return 'auth-user-pass-verify ' . self::hookValue($profile);
	}


	/**
	 * Remove directives written by releases that predate the core configuration hook.
	 *
	 * @param array<string, SimpleXMLElement> $instances
	 */
	private static function removeLegacyFlags(array $instances): bool
	{
		$changed = false;
		foreach ($instances as $instance) {
			$original = self::flags($instance);
			$hadOwnedHook = false;
			$flags = [];
			foreach ($original as $flag) {
				if (self::isOwnedHook($flag)) {
					$hadOwnedHook = true;
					continue;
				}
				$flags[] = $flag;
			}
			if ($hadOwnedHook) {
				$flags = array_values(array_filter(
					$flags,
					static fn(string $flag): bool => $flag !== self::OPTIONAL_DIRECTIVE,
				));
			}
			if ($flags !== $original) {
				self::setFlags($instance, $flags);
				$changed = true;
			}
		}

		return $changed;
	}


	private static function isOwnedHook(string $flag): bool
	{
		$path = preg_quote(self::HOOK, '~');
		return preg_match('~^auth-user-pass-verify "' . $path . '(?: [A-Za-z0-9_]{1,32})?" via-file$~D', $flag) === 1;
	}


	/**
	 * @param array<string, string> $desired
	 * @return array<string, array<string, string>>
	 */
	private static function manifest(array $desired): array
	{
		$result = [];
		foreach ($desired as $uuid => $profile) {
			$result[$uuid] = [
				'profile' => $profile,
				'auth_directive' => self::hookDirective($profile),
				'optional_directive' => self::OPTIONAL_DIRECTIVE,
				'config_file' => "/var/etc/openvpn/instance-{$uuid}.conf",
				'pid_file' => "/var/run/ovpn-instance-{$uuid}.pid",
			];
		}

		return $result;
	}


	/** @return array<string, string> instance UUID => profile name */
	private static function desiredInstances(SimpleXMLElement $config): array
	{
		$desired = [];
		$profiles = $config->xpath('/opnsense/OPNsense/SSO/settings/vpn/profiles/profile') ?: [];
		foreach ($profiles as $profile) {
			if ((string)($profile->enabled ?? '') !== '1') {
				continue;
			}
			$name = trim((string)($profile->name ?? ''));
			$uuids = array_unique(array_filter(array_map(
				'trim',
				explode(',', (string)($profile->openvpn_instance ?? '')),
			), 'strlen'));
			if ($uuids === []) {
				continue;
			}
			if (preg_match('/^[A-Za-z0-9_]{1,32}$/D', $name) !== 1) {
				throw new RuntimeException("Invalid os-sso OpenVPN profile name '{$name}'");
			}
			foreach ($uuids as $uuid) {
				if (preg_match('/^[0-9a-f-]{36}$/D', $uuid) !== 1) {
					throw new RuntimeException("Invalid OpenVPN instance UUID '{$uuid}' in profile '{$name}'");
				}
				if (isset($desired[$uuid])) {
					throw new RuntimeException(
						"OpenVPN instance '{$uuid}' is selected by both '{$desired[$uuid]}' and '{$name}'"
					);
				}
				$desired[$uuid] = $name;
			}
		}

		return $desired;
	}


	/** @return array<string, SimpleXMLElement> */
	private static function openVpnInstances(SimpleXMLElement $config): array
	{
		$result = [];
		$instances = $config->xpath('/opnsense/OPNsense/OpenVPN/Instances/Instance') ?: [];
		foreach ($instances as $instance) {
			$uuid = trim((string)($instance->attributes()['uuid'] ?? ''));
			if ($uuid !== '') {
				$result[$uuid] = $instance;
			}
		}

		return $result;
	}


	/** @return string[] */
	private static function flags(SimpleXMLElement $instance): array
	{
		$value = trim((string)($instance->various_flags ?? ''));
		if ($value === '') {
			return [];
		}

		return array_values(array_filter(array_map('trim', explode(',', $value)), 'strlen'));
	}


	/** @param string[] $flags */
	private static function setFlags(SimpleXMLElement $instance, array $flags): void
	{
		$value = implode(',', $flags);
		if (isset($instance->various_flags)) {
			$instance->various_flags = $value;
		} else {
			$instance->addChild('various_flags', $value);
		}
	}


	/** @param array<string, array<string, string>> $instances */
	private static function writeManifest(array $instances, string $path): void
	{
		$directory = dirname($path);
		// @ - another process may create the directory between both checks.
		if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
			throw new RuntimeException("Cannot create OpenVPN integration directory '{$directory}'");
		}
		$data = json_encode(['version' => 1, 'instances' => $instances], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
		if ($data === false) {
			throw new RuntimeException('Cannot encode the OpenVPN integration manifest');
		}
		$temporary = $path . '.' . getmypid() . '.tmp';
		if (file_put_contents($temporary, $data . "\n", LOCK_EX) === false) {
			throw new RuntimeException("Cannot write OpenVPN integration manifest '{$temporary}'");
		}
		chmod($temporary, 0600);
		if (!rename($temporary, $path)) {
			@unlink($temporary); // @ - best-effort cleanup after a failed rename
			throw new RuntimeException("Cannot replace OpenVPN integration manifest '{$path}'");
		}
	}
}
