<?php

declare(strict_types=1);

use OPNsense\Auth\AuthenticationFactory;
use OPNsense\SSO\Api\OidcController;
use OPNsense\SSO\SessionRegistry;
use OPNsense\SSO\StateDir;
use OPNsense\SSO\Test\Tree;

T::group('Front-channel logout: the controller revokes only its provider');
if (!stateDirUsable()) {
	T::skip('front-channel controller revocation', 'state directory unavailable');
	return;
}

require_once dirname(__DIR__, 2) . '/src/opnsense/mvc/app/controllers/OPNsense/SSO/Api/OidcController.php';

$issuer = 'https://frontchannel.idp.example/realm';
$provider = new class ($issuer) {
	public function __construct(public string $ssoIssuer)
	{
	}


	public function getType(): string
	{
		return 'oidc';
	}


	public function __get(string $name): mixed
	{
		return match ($name) {
			'ssoClientId' => 'firewall',
			'ssoBaseUrl' => 'https://firewall.example',
			default => null,
		};
	}
};
$cache = StateDir::path('oidc') . '/' . hash('sha256', 'disco_' . $issuer) . '.json';
file_put_contents($cache, json_encode([
	'issuer' => $issuer,
	'authorization_endpoint' => $issuer . '/auth',
	'token_endpoint' => $issuer . '/token',
]));
$savedQuery = $_GET;
$savedServer = $_SERVER;
try {
	Tree::build([]);
	SessionRegistry::destroyAll();
	foreach (['one', 'two'] as $name) {
		SessionRegistry::recordGrant([
			'kind' => SessionRegistry::PORTAL,
			'username' => 'guest',
			'cp_session' => 'frontchannel-' . $name,
			'issuer' => $issuer,
			'provider' => $name,
			'sub' => 'alice',
			'sid' => 'shared-session',
		]);
	}
	AuthenticationFactory::$providers['one'] = $provider;
	$controller = new OidcController();
	$controller->request = new class {
		public function get(string $name): mixed
		{
			return $_GET[$name] ?? null;
		}
	};
	$controller->response = new class {
		public int $status = 200;


		public function setHeader(string $name, string $value): void
		{
		}


		public function setStatusCode(int $status, string $reason): void
		{
			$this->status = $status;
		}
	};
	$_GET = ['provider' => 'one', 'iss' => $issuer, 'sid' => 'shared-session'];
	$_SERVER['REMOTE_ADDR'] = '192.0.2.251';
	$controller->frontchannelAction();
	eq(200, $controller->response->status, 'the front-channel callback succeeds');
	eq(['two'], array_column(SessionRegistry::listActive(), 'provider'), 'the same issuer and sid on another provider survive');
	$_GET['iss'] = $issuer . '/';
	$controller->frontchannelAction();
	eq(400, $controller->response->status, 'the controller rejects a distinct issuer');
	eq(1, count(SessionRegistry::listActive()), 'a rejected callback revokes no other grant');
} finally {
	SessionRegistry::destroyAll();
	AuthenticationFactory::$providers = [];
	$_GET = $savedQuery;
	$_SERVER = $savedServer;
	unlink($cache);
}
