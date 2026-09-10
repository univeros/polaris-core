<?php

declare(strict_types=1);

namespace Polaris\Symfony;

use PDO;
use Polaris\Config\Secrets;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Exception\InvalidConfigException;
use Polaris\Pdo\PdoAdapter;
use Psr\Cache\CacheItemPoolInterface;
use Psr\SimpleCache\CacheInterface;
use Symfony\Component\Cache\Psr16Cache;

use function file_get_contents;
use function get_debug_type;
use function is_file;
use function is_string;
use function method_exists;
use function sprintf;
use function str_starts_with;

/**
 * The service factories the bundle wires: secrets from the configuration (values or PEM files), the
 * PDO handle and the database adapter from a DSN or from the application's connection service (a PDO,
 * a Doctrine DBAL connection or a Polaris adapter), the PSR-16 cache from a PSR-6 pool.
 */
final class Factory
{
    private const array SECRET_KEYS = [
        'app_key' => 'APP_KEY',
        'jwt_private_key' => 'AUTH_JWT_PRIVATE_KEY',
        'jwt_public_key' => 'AUTH_JWT_PUBLIC_KEY',
        'jwt_kid' => 'AUTH_JWT_KID',
        'jwt_previous_public_key' => 'AUTH_JWT_PREVIOUS_PUBLIC_KEY',
        'jwt_previous_kid' => 'AUTH_JWT_PREVIOUS_KID',
    ];

    /**
     * @param array<string, mixed> $secrets
     */
    public static function secrets(array $secrets, string $projectDir): Secrets
    {
        $env = [];
        foreach (self::SECRET_KEYS as $key => $name) {
            $value = self::string($secrets[$key] ?? null) ?? self::file(self::string($secrets[$key . '_file'] ?? null), $key, $projectDir);
            if ($value !== null) {
                $env[$name] = $value;
            }
        }

        return Secrets::fromEnvironment($env);
    }

    public static function connect(?string $dsn, ?string $user, ?string $password): PDO
    {
        if ($dsn === null || $dsn === '') {
            throw new InvalidConfigException('polaris.database.dsn is empty.');
        }
        $pdo = new PDO($dsn, $user, $password);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        if (str_starts_with($dsn, 'sqlite:')) {
            $pdo->exec('PRAGMA foreign_keys = ON');
        }

        return $pdo;
    }

    /**
     * The PDO handle behind the application's connection service.
     */
    public static function pdo(object $connection): PDO
    {
        if ($connection instanceof PDO) {
            return $connection;
        }
        if ($connection instanceof PdoAdapter) {
            return $connection->pdo();
        }
        // Doctrine DBAL 3.3+ without depending on it.
        if (method_exists($connection, 'getNativeConnection')) {
            $native = $connection->getNativeConnection();
            if ($native instanceof PDO) {
                return $native;
            }
        }

        throw new InvalidConfigException(sprintf('polaris.database.service must be a PDO, a Doctrine DBAL connection over PDO or a Polaris adapter, got %s.', get_debug_type($connection)));
    }

    public static function adapter(object $connection): DatabaseAdapter
    {
        return $connection instanceof DatabaseAdapter ? $connection : new PdoAdapter(self::pdo($connection));
    }

    public static function cache(object $cache): CacheInterface
    {
        if ($cache instanceof CacheInterface) {
            return $cache;
        }
        if ($cache instanceof CacheItemPoolInterface) {
            return new Psr16Cache($cache);
        }

        throw new InvalidConfigException(sprintf('polaris.cache must be a PSR-16 cache or a PSR-6 pool, got %s.', get_debug_type($cache)));
    }

    private static function file(?string $path, string $key, string $projectDir): ?string
    {
        if ($path === null) {
            return null;
        }
        $absolute = str_starts_with($path, '/') ? $path : $projectDir . '/' . $path;
        if (!is_file($absolute)) {
            throw new InvalidConfigException(sprintf('polaris.secrets.%s_file points to a missing file: %s', $key, $absolute));
        }

        return (string) file_get_contents($absolute);
    }

    private static function string(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }
}
