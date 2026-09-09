<?php

declare(strict_types=1);

namespace Polaris\Tests\Contract;

use function count;
use function is_array;
use function is_string;
use function json_encode;
use function ksort;
use function preg_match;
use function str_starts_with;
use function strlen;
use function usort;

/**
 * Makes two responses comparable across runs: every value that is minted per run (ids, tokens,
 * secrets, codes, timestamps, rate-limit clocks) collapses to a placeholder; keys are sorted.
 */
final class Normalizer
{
    private const array VOLATILE_HEADERS = ['date', 'x-ratelimit-reset', 'retry-after', 'x-ratelimit-remaining'];

    /**
     * @param array<string, mixed> $response  {status, headers, body}
     * @return array<string, mixed>
     */
    public static function response(array $response): array
    {
        $headers = [];
        foreach ((array) ($response['headers'] ?? []) as $name => $values) {
            $lower = strtolower((string) $name);
            if (in_array($lower, self::VOLATILE_HEADERS, true)) {
                continue;
            }
            $headers[$lower] = is_array($values) ? array_values($values) : [$values];
        }
        ksort($headers);

        return [
            'status' => $response['status'] ?? null,
            'headers' => $headers,
            'body' => self::value($response['body'] ?? null, ''),
        ];
    }

    /**
     * @param list<mixed> $values
     */
    private static function allArrays(array $values): bool
    {
        foreach ($values as $v) {
            if (!is_array($v)) {
                return false;
            }
        }

        return true;
    }

    public static function value(mixed $value, string $key): mixed
    {
        if (is_array($value)) {
            if (in_array($key, ['recovery_codes', 'codes'], true)) {
                return ['<' . count($value) . ' codes>'];
            }
            $out = [];
            foreach ($value as $k => $v) {
                $out[$k] = self::value($v, is_string($k) ? $k : $key);
            }
            if (!array_is_list($out)) {
                ksort($out);
            } elseif ($out !== [] && self::allArrays($out)) {
                // 1.0 never ordered its record lists (the driver's row order leaked through), so the
                // contract holds the set of records, not their order.
                usort($out, static fn(array $a, array $b): int => json_encode($a) <=> json_encode($b));
            }

            return $out;
        }
        if (!is_string($value)) {
            return $value;
        }
        if (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $value) === 1) {
            return '<uuid>';
        }
        if (preg_match('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', $value) === 1 && strlen($value) > 60) {
            return '<jwt>';
        }
        if (preg_match('/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}/', $value) === 1) {
            return '<datetime>';
        }
        if (str_starts_with($value, 'otpauth://')) {
            return '<otpauth>';
        }
        if (str_starts_with($value, 'data:image/') || str_starts_with($value, '<svg')) {
            return '<image>';
        }
        if (in_array($key, ['refresh_token', 'token', 'secret', 'code', 'mfa_token', 'access_token', 'invite_token', 'kid', 'n', 'e', 'x', 'y', 'qr', 'qr_code', 'qr_svg', 'otpauth_uri', 'uri'], true)) {
            return '<' . $key . '>';
        }
        if (preg_match('/^[A-Za-z0-9_\-+\/=]{32,}$/', $value) === 1) {
            return '<opaque>';
        }
        if (preg_match('/^\+\d \*{3} \*{3} \d{4}$/', $value) === 1) {
            return $value;
        }

        return $value;
    }
}
