<?php

declare(strict_types=1);

namespace Polaris\Passkey;

use function base64_decode;
use function base64_encode;
use function rtrim;
use function strtr;

/**
 * The encoding WebAuthn's JSON uses for bytes.
 */
final class Base64Url
{
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    public static function decode(string $encoded): ?string
    {
        $decoded = base64_decode(strtr($encoded, '-_', '+/'), true);

        return $decoded === false ? null : $decoded;
    }
}
