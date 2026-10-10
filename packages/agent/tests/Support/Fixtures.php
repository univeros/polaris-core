<?php

declare(strict_types=1);

namespace Polaris\Agent\Tests\Support;

use Firebase\JWT\JWT;
use Polaris\Agent\AgentKey;
use Polaris\Agent\Configuration;

use function explode;
use function json_decode;
use function openssl_pkey_export;
use function openssl_pkey_get_details;
use function openssl_pkey_new;

use const OPENSSL_KEYTYPE_RSA;

/** The shapes the unit tests share: a configuration document, grants, approvals, receipts and a server key. */
final class Fixtures
{
    public const string MOUNT = 'https://auth.polaris.test/api';

    public static function configuration(): Configuration
    {
        $url = static fn(string $path): string => self::MOUNT . $path;

        return new Configuration([
            'version' => '1.0-draft',
            'provider_name' => 'Polaris test',
            'description' => 'The unit tests',
            'issuer' => 'https://auth.polaris.test',
            'default_location' => $url('/agents/execute'),
            'algorithms' => ['ES256', 'EdDSA'],
            'modes' => ['delegated', 'autonomous'],
            'approval_methods' => ['device_authorization', 'ciba', 'in_app'],
            'approval_strengths' => ['low' => 'session', 'medium' => 'session', 'high' => 'step_up'],
            'endpoints' => [
                'register' => $url('/agents/register'), 'enroll' => $url('/agents/enroll'), 'capabilities' => $url('/agents/capabilities'),
                'execute' => $url('/agents/execute'), 'request_capability' => $url('/agents/grants/request'), 'status' => $url('/agents/session'),
                'revoke' => $url('/agents'), 'grants' => $url('/agents/grants'), 'approvals' => $url('/agents/approvals'), 'receipts' => $url('/agents/receipts'),
                'token' => $url('/oauth2/token'), 'mcp' => $url('/mcp'),
            ],
            'token_endpoint' => $url('/oauth2/token'),
        ]);
    }

    /**
     * @param array<string, mixed> $fields
     * @return array<string, mixed>
     */
    public static function grant(array $fields = []): array
    {
        return [
            'id' => 'g1', 'agent_id' => 'a1', 'capability' => 'demo.echo', 'constraints' => [], 'budget' => ['kind' => 'count', 'total' => 100, 'remaining' => 100, 'field' => null],
            'status' => 'active', 'granted_by' => null, 'approved_via' => 'auto', 'approval_id' => null, 'expires_at' => null,
            'created_at' => '2026-10-10T10:00:00+00:00', 'updated_at' => '2026-10-10T10:00:00+00:00', ...$fields,
        ];
    }

    /**
     * @param array<string, mixed> $fields
     * @return array<string, mixed>
     */
    public static function approval(array $fields = []): array
    {
        return ['id' => 'ap1', 'method' => 'in_app', 'strength' => 'session', 'user_code' => null, 'verification_uri' => null, 'verification_uri_complete' => null, 'expires_in' => 60, 'interval' => 5, 'binding_message' => null, ...$fields];
    }

    /**
     * @param array<string, mixed> $fields
     * @return array<string, mixed>
     */
    public static function receipt(array $fields = []): array
    {
        return [
            'id' => 'r1', 'agent_id' => 'a1', 'seq' => 1, 'grant_id' => 'g1', 'capability' => 'demo.echo', 'input_hash' => 'ab', 'outcome' => 'success',
            'budget_before' => 100, 'budget_after' => 99, 'prev_hash' => null, 'hash' => '', 'signature' => '', 'created_at' => '2026-10-10T10:00:00+00:00', ...$fields,
        ];
    }

    /**
     * A server RS256 key (core's default signer): the PEM and the JWKS listing its public JWK.
     *
     * @return array{pem: string, jwks: array<string, mixed>}
     */
    public static function serverKey(string $kid = 'server-key'): array
    {
        $rsa = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        if ($rsa === false || !openssl_pkey_export($rsa, $pem)) {
            throw new \RuntimeException('openssl could not generate an RSA key.');
        }
        $details = openssl_pkey_get_details($rsa);
        $jwk = ['kty' => 'RSA', 'use' => 'sig', 'alg' => 'RS256', 'kid' => $kid, 'n' => AgentKey::base64Url((string) $details['rsa']['n']), 'e' => AgentKey::base64Url((string) $details['rsa']['e'])];

        return ['pem' => (string) $pem, 'jwks' => ['keys' => [['kty' => 'RSA', 'use' => 'sig', 'alg' => 'RS256', 'kid' => 'other', 'n' => 'AQAB', 'e' => 'AQAB'], $jwk]]];
    }

    /**
     * A receipt+jwt as `Polaris\Agents\Receipts::sign` makes it, over the given hash.
     *
     * @param array<string, mixed> $receipt
     */
    public static function signReceipt(string $pem, array $receipt, string $hash, string $kid = 'server-key'): string
    {
        return JWT::encode(['iss' => 'https://auth.polaris.test', 'iat' => 1760090400, 'receipt_hash' => $hash, 'receipt_id' => $receipt['id'], 'agent_id' => $receipt['agent_id'], 'seq' => $receipt['seq']], $pem, 'RS256', $kid, ['typ' => 'receipt+jwt']);
    }

    /**
     * The decoded header and claims of a compact JWS, unverified.
     *
     * @return array{header: array<string, mixed>, claims: array<string, mixed>}
     */
    public static function decode(string $jws): array
    {
        [$header, $payload] = explode('.', $jws);

        return ['header' => (array) json_decode(JWT::urlsafeB64Decode($header), true), 'claims' => (array) json_decode(JWT::urlsafeB64Decode($payload), true)];
    }
}
