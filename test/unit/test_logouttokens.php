<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use OPNsense\SSO\Protocol\JwtProtocol;
use OPNsense\SSO\Protocol\OidcProtocol;
use OPNsense\SSO\StateDir;

if (!stateDirUsable()) {
	T::skip('signed logout tokens and replay protection', 'state directory unavailable');
	return;
}
T::group('OIDC logout: signed tokens require exp, jti and valid typed claims');
$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
openssl_pkey_export($key, $pem);
$details = openssl_pkey_get_details($key);
$encode = fn(string $value): string => rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
$jwks = ['keys' => [['kty' => 'RSA', 'kid' => 'logout-fixture', 'alg' => 'RS256', 'n' => $encode($details['rsa']['n']), 'e' => $encode($details['rsa']['e'])]]];
$issuer = 'https://logout-test.example';
$protocolForClient = function (string $client) use ($issuer, $jwks): OidcProtocol {
	$protocol = new OidcProtocol(['issuer' => $issuer, 'client_id' => $client]);
	(new ReflectionProperty($protocol, 'discovery'))->setValue($protocol, ['issuer' => $issuer, 'jwks_uri' => $issuer . '/jwks', 'id_token_signing_alg_values_supported' => ['RS256']]);
	(new ReflectionMethod($protocol, 'cacheSet'))->invoke($protocol, 'jwks_' . $issuer . '/jwks', $jwks);
	return $protocol;
};
$protocol = $protocolForClient('client-a');
$base = ['iss' => $issuer, 'aud' => 'client-a', 'iat' => time(), 'exp' => time() + 240, 'sub' => 'alice', 'sid' => 'session-a', 'events' => ['http://schemas.openid.net/event/backchannel-logout' => (object)[]]];
$sign = fn(array $claims): string => JWT::encode($claims, $pem, 'RS256', 'logout-fixture');
foreach ([
	'missing exp' => ['exp' => null],
	'string exp' => ['exp' => (string)(time() + 240)],
	'missing jti' => ['jti' => null],
	'empty jti' => ['jti' => ''],
	'numeric jti' => ['jti' => 42],
	'array sub' => ['sub' => ['alice']],
	'empty sid' => ['sid' => ''],
	'numeric sid' => ['sid' => 42],
	'null sid' => ['sid' => null],
	'null nonce' => ['nonce' => null],
	'string iat' => ['iat' => (string)time()],
	'future iat despite past nbf' => ['iat' => time() + 120, 'nbf' => time() - 1],
	'nonempty event' => ['events' => ['http://schemas.openid.net/event/backchannel-logout' => (object)['unexpected' => true]]],
	'invalid event type' => ['events' => ['http://schemas.openid.net/event/backchannel-logout' => true]],
] as $label => $changes) {
	$claims = array_replace($base + ['jti' => bin2hex(random_bytes(16))], $changes);
	throws(fn() => $protocol->validateLogoutToken($sign($claims)), '', 'refuses a signed token with ' . $label);
}
$token = $sign($base + ['jti' => bin2hex(random_bytes(16))]);
eq(['sub' => 'alice', 'sid' => 'session-a'], $protocol->validateLogoutToken($token), 'a valid signed logout token is accepted');
throws(fn() => $protocol->validateLogoutToken($token), 'replay', 'the same signed token is single use');

T::group('OIDC logout: replay protection covers clock skew and isolates clients');
$claims = array_replace($base, ['aud' => ['client-a', 'client-b'], 'jti' => bin2hex(random_bytes(16)), 'iat' => time() + 45, 'exp' => time() + 400, 'nbf' => time() - 1]);
$token = $sign($claims);
$protocol->validateLogoutToken($token);
$marker = StateDir::path('oidc-logout') . '/' . hash('sha256', json_encode([$issuer, 'client-a', $claims['jti']], JSON_THROW_ON_ERROR)) . '.marker';
touch($marker, time() - 301);
throws(fn() => $protocol->validateLogoutToken($token), 'replay', 'a skewed token cannot outlive its replay marker');
eq('alice', $protocolForClient('client-b')->validateLogoutToken($token)['sub'], 'a token legitimately addressed to another client has a separate replay scope');
$legacyJti = bin2hex(random_bytes(16));
$legacyMarker = StateDir::path('oidc-logout') . '/' . hash('sha256', $issuer . '|' . $legacyJti) . '.marker';
touch($legacyMarker);
throws(fn() => $protocol->validateLogoutToken($sign($base + ['jti' => $legacyJti])), 'replay', 'an upgrade preserves an older replay marker');

T::group('JWT forward auth: an unfinished replay marker must remain consumed');
$jwtProtocol = new JwtProtocol(['issuer' => $issuer, 'audience' => 'forward-auth', 'public_key' => $details['key'], 'single_use' => true]);
$jti = bin2hex(random_bytes(16));
$claims = ['iss' => $issuer, 'aud' => 'forward-auth', 'iat' => time(), 'exp' => time() + 300, 'sub' => 'alice', 'jti' => $jti];
$marker = StateDir::path('jwt-seen') . '/' . hash('sha256', $issuer . '|jti:' . $jti) . '.json';
$writer = fopen($marker, 'x');
try {
	throws(fn() => $jwtProtocol->verify($sign($claims)), 'replay', 'a concurrent empty marker is not deleted and reused');
	truthy(is_file($marker), 'the exclusive marker remains reserved by its creator');
} finally {
	fclose($writer);
	unlink($marker);
}
$claims['jti'] = bin2hex(random_bytes(16));
$token = $sign($claims);
eq('alice', $jwtProtocol->verify($token)->subject, 'a fresh JWT is accepted');
throws(fn() => $jwtProtocol->verify($token), 'replay', 'a complete marker also blocks replay');
