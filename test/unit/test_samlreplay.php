<?php

declare(strict_types=1);

use OneLogin\Saml2\Utils;
use OPNsense\SSO\Protocol\SamlProtocol;
use OPNsense\SSO\StateDir;

T::group('SAML: replay protection covers the signed assertion validity');
if (!stateDirUsable()) {
    T::skip('signed assertion replay regression', 'state directory unavailable');
    return;
}

$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
openssl_pkey_export($key, $keyPem);
$certificateRequest = openssl_csr_new(['commonName' => 'audit-idp.example'], $key, ['digest_alg' => 'sha256']);
$certificate = openssl_csr_sign($certificateRequest, null, $key, 1, ['digest_alg' => 'sha256']);
openssl_x509_export($certificate, $certificatePem);
$instant = gmdate('Y-m-d\TH:i:s\Z', time() - 30);
$before = gmdate('Y-m-d\TH:i:s\Z', time() - 60);
$expires = gmdate('Y-m-d\TH:i:s\Z', time() + 3600);
$assertionId = '_audit-valid-hour-' . getmypid();
$acs = 'https://firewall.example/api/sso/saml/acs';
$entity = 'https://firewall.example/saml';
$idp = 'https://idp.example/saml';
$assertion = <<<XML
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="$assertionId" Version="2.0" IssueInstant="$instant">
<saml:Issuer>$idp</saml:Issuer>
<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">alice</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="$expires" Recipient="$acs"/></saml:SubjectConfirmation></saml:Subject>
<saml:Conditions NotBefore="$before" NotOnOrAfter="$expires"><saml:AudienceRestriction><saml:Audience>$entity</saml:Audience></saml:AudienceRestriction></saml:Conditions>
<saml:AuthnStatement AuthnInstant="$instant" SessionIndex="_audit-session" SessionNotOnOrAfter="$expires"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>
<saml:AttributeStatement><saml:Attribute Name="username"><saml:AttributeValue>alice</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
</saml:Assertion>
XML;
$signed = Utils::addSign($assertion, $keyPem, $certificatePem);
$document = new DOMDocument();
$document->loadXML($signed);
$assertionId = $document->documentElement->getAttribute('ID');
$signature = $document->getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')->item(0);
$issuer = $document->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Issuer')->item(0);
$document->documentElement->insertBefore($signature, $issuer->nextSibling);
$assertion = $document->saveXML($document->documentElement);
$response = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_audit-response" Version="2.0" IssueInstant="' . $instant . '" Destination="' . $acs . '">'
	. '<saml:Issuer>' . $idp . '</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
	. $assertion . '</samlp:Response>';
$_SERVER['HTTP_HOST'] = 'firewall.example';
$_SERVER['SERVER_PORT'] = '443';
$_SERVER['HTTPS'] = 'on';
$_SERVER['REQUEST_URI'] = '/api/sso/saml/acs';
$_POST = ['SAMLResponse' => base64_encode($response)];
$protocol = new SamlProtocol([
	'base_url' => 'https://firewall.example', 'sp_entity_id' => $entity, 'acs_url' => $acs,
	'idp_entity_id' => $idp, 'idp_sso_url' => 'https://idp.example/sso', 'idp_x509' => $certificatePem,
	'allow_idp_initiated' => true,
]);
$first = nothrow(fn() => $protocol->handleCallback($_POST), 'the signed IdP-initiated response is accepted');
eq('alice', $first?->username, 'the validated assertion carries the expected identity');
throws(fn() => $protocol->handleCallback($_POST), 'replay', 'an immediate replay is refused');
$marker = StateDir::path('saml') . '/seen-' . hash('sha256', $assertionId) . '.json';
touch($marker, time() - 601);
clearstatcache(true, $marker);
(new ReflectionMethod($protocol, 'sweepStale'))->invoke($protocol);
throws(fn() => $protocol->handleCallback($_POST), 'replay', 'the same still-valid signed response remains blocked after ten minutes');
$markerData = json_decode((string)file_get_contents($marker), true);
truthy(($markerData['expires_at'] ?? 0) >= strtotime($expires), 'the marker lasts at least as long as the signed assertion');
unlink($marker);
$_POST = [];
