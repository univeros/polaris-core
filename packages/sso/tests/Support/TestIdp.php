<?php

declare(strict_types=1);

namespace Polaris\Sso\Tests\Support;

use OneLogin\Saml2\Utils;
use OpenSSLAsymmetricKey;

use function base64_encode;
use function gmdate;
use function gzdeflate;
use function htmlspecialchars;
use function openssl_csr_new;
use function openssl_csr_sign;
use function openssl_pkey_export;
use function openssl_pkey_new;
use function openssl_sign;
use function openssl_x509_export;
use function str_replace;
use function time;
use function urlencode;
use function sprintf;
use function uniqid;

use const OPENSSL_ALGO_SHA256;
use const OPENSSL_KEYTYPE_RSA;

/**
 * A SAML identity provider for the tests: a self-signed certificate made once per process, signed
 * responses and logout requests built for a service provider.
 */
final class TestIdp
{
    public const string ENTITY_ID = 'https://idp.example/metadata';
    public const string SSO_URL = 'https://idp.example/sso';
    public const string SLO_URL = 'https://idp.example/slo';

    private static ?self $instance = null;

    private function __construct(public readonly string $certificate, public readonly string $privateKey)
    {
    }

    public static function get(): self
    {
        if (self::$instance === null) {
            $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
            if (!$key instanceof OpenSSLAsymmetricKey) {
                throw new \RuntimeException('openssl could not make a key');
            }
            $csr = openssl_csr_new(['commonName' => 'idp.example'], $key, ['digest_alg' => 'sha256']);
            $x509 = $csr === false ? false : openssl_csr_sign($csr, null, $key, 365, ['digest_alg' => 'sha256']);
            $certificate = '';
            $privateKey = '';
            if ($x509 === false || !openssl_x509_export($x509, $certificate) || !openssl_pkey_export($key, $privateKey)) {
                throw new \RuntimeException('openssl could not make a certificate');
            }
            self::$instance = new self($certificate, $privateKey);
        }

        return self::$instance;
    }

    /**
     * The certificate as a provider stores it: base64 without the PEM armour.
     */
    public function certificateBody(): string
    {
        return Utils::formatCert($this->certificate, false);
    }

    /**
     * A signed Response (the message signature covers the assertion) with one assertion.
     *
     * @param array<string, string> $attributes
     * @param array<string, mixed> $options `issuer`, `audience`, `destination`, `in_response_to`, `not_on_or_after` (seconds from now), `not_before` (seconds from now), `assertion_id`, `sign` (bool), `key` (another private key), `extra_assertion` (bool)
     */
    public function response(string $spEntityId, string $acsUrl, string $nameId, array $attributes = [], array $options = []): string
    {
        $now = time();
        $issuer = htmlspecialchars((string) ($options['issuer'] ?? self::ENTITY_ID));
        $audience = htmlspecialchars((string) ($options['audience'] ?? $spEntityId));
        $destination = htmlspecialchars((string) ($options['destination'] ?? $acsUrl));
        $inResponseTo = isset($options['in_response_to']) ? sprintf(' InResponseTo="%s"', htmlspecialchars((string) $options['in_response_to'])) : '';
        $notOnOrAfter = gmdate('Y-m-d\TH:i:s\Z', $now + (int) ($options['not_on_or_after'] ?? 300));
        $notBefore = gmdate('Y-m-d\TH:i:s\Z', $now + (int) ($options['not_before'] ?? -60));
        $issueInstant = gmdate('Y-m-d\TH:i:s\Z', $now);
        $assertionId = (string) ($options['assertion_id'] ?? '_' . uniqid('a', true));
        $attributeXml = '';
        foreach ($attributes as $name => $value) {
            $attributeXml .= sprintf('<saml:Attribute Name="%s"><saml:AttributeValue xsi:type="xs:string">%s</saml:AttributeValue></saml:Attribute>', htmlspecialchars($name), htmlspecialchars($value));
        }
        $attributeXml = $attributeXml === '' ? '' : '    <saml:AttributeStatement>' . $attributeXml . '</saml:AttributeStatement>';
        $assertion = <<<XML
<saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="{$assertionId}" Version="2.0" IssueInstant="{$issueInstant}">
    <saml:Issuer>{$issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{$nameId}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="{$notOnOrAfter}" Recipient="{$destination}"{$inResponseTo}/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{$notBefore}" NotOnOrAfter="{$notOnOrAfter}">
      <saml:AudienceRestriction><saml:Audience>{$audience}</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{$issueInstant}" SessionIndex="session-{$assertionId}">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
{$attributeXml}
  </saml:Assertion>
XML;
        $extra = ($options['extra_assertion'] ?? false) === true ? "\n  " . str_replace($assertionId, $assertionId . 'x', $assertion) : '';
        $responseId = '_' . uniqid('r', true);
        $xml = <<<XML
<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{$responseId}" Version="2.0" IssueInstant="{$issueInstant}" Destination="{$destination}"{$inResponseTo}>
  <saml:Issuer>{$issuer}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  {$assertion}{$extra}
</samlp:Response>
XML;
        if (($options['sign'] ?? true) === true) {
            $xml = Utils::addSign($xml, (string) ($options['key'] ?? $this->privateKey), $this->certificate);
        }

        return base64_encode($xml);
    }

    /**
     * A LogoutRequest for the SP as the redirect binding sends it: deflated, base64-encoded, the query
     * signed (`SigAlg`, `Signature`); or, for the POST binding, with an enveloped signature.
     *
     * @return array<string, string>
     */
    public function logoutRequest(string $sloUrl, string $nameId, bool $redirect = true, ?string $relayState = null, bool $sign = true): array
    {
        $now = gmdate('Y-m-d\TH:i:s\Z');
        $id = '_' . uniqid('l', true);
        $issuer = htmlspecialchars(self::ENTITY_ID);
        $xml = <<<XML
<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{$id}" Version="2.0" IssueInstant="{$now}" Destination="{$sloUrl}">
  <saml:Issuer>{$issuer}</saml:Issuer>
  <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{$nameId}</saml:NameID>
  <samlp:SessionIndex>session-1</samlp:SessionIndex>
</samlp:LogoutRequest>
XML;
        if (!$redirect) {
            return ['SAMLRequest' => base64_encode($sign ? Utils::addSign($xml, $this->privateKey, $this->certificate) : $xml)];
        }
        $message = ['SAMLRequest' => base64_encode((string) gzdeflate($xml))];
        if ($relayState !== null) {
            $message['RelayState'] = $relayState;
        }
        if ($sign) {
            $message['SigAlg'] = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
            $query = 'SAMLRequest=' . urlencode($message['SAMLRequest']) . ($relayState === null ? '' : '&RelayState=' . urlencode($relayState)) . '&SigAlg=' . urlencode($message['SigAlg']);
            $signature = '';
            openssl_sign($query, $signature, $this->privateKey, OPENSSL_ALGO_SHA256);
            $message['Signature'] = base64_encode($signature);
        }

        return $message;
    }
}
