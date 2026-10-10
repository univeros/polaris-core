<?php

declare(strict_types=1);

namespace Polaris\Agent;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Throwable;

use function array_is_list;
use function explode;
use function hash;
use function hash_equals;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use function ksort;

use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;

/**
 * What `GET /agents/receipts/{id}/verify` does, locally: the hash recomputed over the canonical JSON of
 * the receipt's fields (keys sorted at every level, slashes unescaped, as `Polaris\Agents\Receipts`
 * makes it), the `receipt+jwt` signature verified with the server's JWKS and bound to this receipt,
 * and the link to the previous receipt when given.
 */
final class Receipts
{
    public const string TYP = 'receipt+jwt';
    public const array HASHED = ['agent_id', 'budget_after', 'budget_before', 'capability', 'created_at', 'grant_id', 'id', 'input_hash', 'outcome', 'prev_hash', 'seq'];

    private function __construct()
    {
    }

    /**
     * @param array<string, mixed> $receipt as the chain lists it (`GET /agents/{id}/receipts`) or the verify route returns it
     * @param array<string, mixed> $jwks the server's JWK Set (`/auth/.well-known/jwks.json`)
     * @param array<string, mixed>|null $previous
     * @return array{valid: bool, checks: array{hash: bool, signature: bool, chain: bool}}
     */
    public static function verify(array $receipt, array $jwks, ?array $previous = null): array
    {
        $recomputed = self::hashOf($receipt);
        $hash = is_string($receipt['hash'] ?? null) && hash_equals($recomputed, $receipt['hash']);
        $signature = self::signatureVouches($receipt, $jwks, $recomputed);
        $seq = $receipt['seq'] ?? null;
        $prev = $receipt['prev_hash'] ?? null;
        if ($seq === 1) {
            $chain = $prev === null;
        } elseif ($previous === null) {
            $chain = is_string($prev);
        } else {
            $chain = ($previous['agent_id'] ?? null) === ($receipt['agent_id'] ?? null) && ($previous['seq'] ?? null) === (int) $seq - 1 && is_string($prev) && hash_equals(self::hashOf($previous), $prev);
        }

        return ['valid' => $hash && $signature && $chain, 'checks' => ['hash' => $hash, 'signature' => $signature, 'chain' => $chain]];
    }

    /**
     * SHA-256 (hex) over the canonical JSON of the receipt's hashed fields.
     *
     * @param array<string, mixed> $receipt
     */
    public static function hashOf(array $receipt): string
    {
        $fields = [];
        foreach (self::HASHED as $field) {
            $fields[$field] = $receipt[$field] ?? null;
        }

        return hash('sha256', self::canonical($fields));
    }

    /**
     * Canonical JSON: keys sorted at every level, slashes unescaped, no whitespace.
     *
     * @param array<mixed> $value
     */
    public static function canonical(array $value): string
    {
        return json_encode(self::sorted($value), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    /**
     * @param array<mixed> $value
     * @return array<mixed>
     */
    private static function sorted(array $value): array
    {
        foreach ($value as $key => $item) {
            if (is_array($item)) {
                $value[$key] = self::sorted($item);
            }
        }
        if (!array_is_list($value)) {
            ksort($value);
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $receipt
     * @param array<string, mixed> $jwks
     */
    private static function signatureVouches(array $receipt, array $jwks, string $recomputed): bool
    {
        $jws = $receipt['signature'] ?? null;
        if (!is_string($jws)) {
            return false;
        }
        try {
            $header = json_decode(JWT::urlsafeB64Decode(explode('.', $jws)[0]), true);
            if (!is_array($header) || ($header['typ'] ?? null) !== self::TYP) {
                return false;
            }
            $claims = (array) JWT::decode($jws, JWK::parseKeySet($jwks, is_string($header['alg'] ?? null) ? $header['alg'] : null));
        } catch (Throwable) {
            return false;
        }

        return is_string($claims['receipt_hash'] ?? null) && hash_equals($recomputed, $claims['receipt_hash'])
            && ($claims['receipt_id'] ?? null) === ($receipt['id'] ?? null)
            && ($claims['agent_id'] ?? null) === ($receipt['agent_id'] ?? null)
            && ($claims['seq'] ?? null) === ($receipt['seq'] ?? null);
    }
}
