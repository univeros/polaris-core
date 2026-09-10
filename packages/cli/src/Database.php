<?php

declare(strict_types=1);

namespace Polaris\Cli;

use PDO;
use Polaris\Contract\Dialect;
use Polaris\Pdo\PdoAdapter;

use function getenv;
use function is_string;
use function str_starts_with;

/**
 * Opens the PDO connection the commands inspect, from `--dsn` or `POLARIS_DSN`.
 */
final class Database
{
    public static function dsn(?string $option): ?string
    {
        if (is_string($option) && $option !== '') {
            return $option;
        }
        $env = getenv('POLARIS_DSN');

        return is_string($env) && $env !== '' ? $env : null;
    }

    public static function connect(string $dsn, ?string $user, ?string $password): PDO
    {
        $pdo = new PDO($dsn, $user ?? (getenv('POLARIS_DB_USER') ?: null), $password ?? (getenv('POLARIS_DB_PASSWORD') ?: null));
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        if (str_starts_with($dsn, 'sqlite:')) {
            $pdo->exec('PRAGMA foreign_keys = ON');
        }

        return $pdo;
    }

    public static function dialectOf(PDO $pdo): Dialect
    {
        return (new PdoAdapter($pdo))->dialect();
    }

    public static function dialect(string $dsn): Dialect
    {
        return match (true) {
            str_starts_with($dsn, 'pgsql:') => Dialect::Postgres,
            str_starts_with($dsn, 'mysql:') => Dialect::Mysql,
            str_starts_with($dsn, 'sqlite:') => Dialect::Sqlite,
            default => Dialect::Mssql,
        };
    }
}
