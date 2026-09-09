<?php

declare(strict_types=1);

namespace Polaris\Config;

use function getenv;
use function in_array;
use function is_string;

/**
 * The environment variables Polaris reads, as the 1.0 module did: the secrets (`APP_KEY`,
 * `AUTH_JWT_*`) and the few auth settings hosts commonly flip (`AUTH_ISSUER`, `AUTH_AUDIENCE`,
 * `AUTH_ACCESS_TOKEN_DENYLIST`, `AUTH_PASSWORD_BREACH_CHECK`).
 */
final class EnvironmentConfig
{
    public const array SECRET_KEYS = ['APP_KEY', 'AUTH_JWT_PRIVATE_KEY', 'AUTH_JWT_PUBLIC_KEY', 'AUTH_JWT_KID', 'AUTH_JWT_PREVIOUS_PUBLIC_KEY', 'AUTH_JWT_PREVIOUS_KID'];

    /**
     * @param array<string, mixed>|null $env defaults to `getenv()`
     */
    public static function secrets(?array $env = null): Secrets
    {
        $values = [];
        foreach (self::SECRET_KEYS as $key) {
            $value = self::read($env, $key);
            if ($value !== null) {
                $values[$key] = $value;
            }
        }

        return Secrets::fromEnvironment($values);
    }

    /**
     * @param array<string, mixed>|null $env defaults to `getenv()`
     * @param array<string, mixed> $overrides merged over the environment-derived array
     */
    public static function auth(?array $env = null, array $overrides = []): AuthConfig
    {
        $issuer = self::read($env, 'AUTH_ISSUER');
        $audience = self::read($env, 'AUTH_AUDIENCE');
        $flag = static fn(?string $value): bool => in_array($value, ['1', 'true', 'on'], true);

        return AuthConfig::fromArray([
            'issuer' => $issuer !== null && $issuer !== '' ? $issuer : 'polaris',
            'audience' => $audience !== null && $audience !== '' ? $audience : null,
            'access_token' => ['denylist' => $flag(self::read($env, 'AUTH_ACCESS_TOKEN_DENYLIST'))],
            'password' => ['breach_check' => $flag(self::read($env, 'AUTH_PASSWORD_BREACH_CHECK'))],
            ...$overrides,
        ]);
    }

    /**
     * @param array<string, mixed>|null $env
     */
    private static function read(?array $env, string $key): ?string
    {
        $value = $env === null ? getenv($key) : ($env[$key] ?? null);

        return is_string($value) ? $value : null;
    }
}
