<?php

declare(strict_types=1);

namespace Polaris\Admin\Principal;

use function explode;
use function inet_pton;
use function intdiv;
use function is_numeric;
use function ord;
use function str_contains;
use function strlen;
use function substr;

/**
 * An API key's allowlist: plain addresses and CIDR blocks, IPv4 and IPv6. Empty allows anywhere; a
 * non-empty list with no client address denies.
 */
final class IpAllowlist
{
    /**
     * @param list<string> $allowlist
     */
    public static function allows(array $allowlist, ?string $ip): bool
    {
        if ($allowlist === []) {
            return true;
        }
        $packed = $ip === null ? false : inet_pton($ip);
        if ($packed === false) {
            return false;
        }
        foreach ($allowlist as $entry) {
            if (self::matches($entry, $packed)) {
                return true;
            }
        }

        return false;
    }

    public static function isValid(string $entry): bool
    {
        [$address, $bits] = str_contains($entry, '/') ? explode('/', $entry, 2) : [$entry, null];
        $packed = inet_pton($address);
        if ($packed === false) {
            return false;
        }

        return $bits === null || (is_numeric($bits) && (int) $bits >= 0 && (int) $bits <= strlen($packed) * 8);
    }

    private static function matches(string $entry, string $packedIp): bool
    {
        [$address, $bits] = str_contains($entry, '/') ? explode('/', $entry, 2) : [$entry, null];
        $packed = inet_pton($address);
        if ($packed === false || strlen($packed) !== strlen($packedIp)) {
            return false;
        }
        $prefix = $bits === null ? strlen($packed) * 8 : (int) $bits;
        $bytes = intdiv($prefix, 8);
        if (substr($packed, 0, $bytes) !== substr($packedIp, 0, $bytes)) {
            return false;
        }
        $remaining = $prefix % 8;
        if ($remaining === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $remaining)) & 0xFF;

        return (ord($packed[$bytes]) & $mask) === (ord($packedIp[$bytes]) & $mask);
    }
}
