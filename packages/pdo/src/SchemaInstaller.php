<?php

declare(strict_types=1);

namespace Polaris\Pdo;

use DateTimeImmutable;
use PDO;
use Polaris\Authorization\PermissionCatalog;
use Polaris\Authorization\PermissionCatalogSeeder;

/**
 * What a host's migration or console command calls to install Polaris on a connection: the tables
 * from the SQL exporter for the connection's dialect, then the permission catalog and the system
 * roles, as `schema:export` plus the seeder would. `schema:diff` proves the result.
 */
final class SchemaInstaller
{
    public static function create(PDO|PdoAdapter $connection, ?DateTimeImmutable $now = null): void
    {
        $adapter = $connection instanceof PdoAdapter ? $connection : new PdoAdapter($connection);
        foreach (SqlSchema::createAll($adapter->dialect()) as $statement) {
            $adapter->exec($statement);
        }
        (new PermissionCatalogSeeder(new PermissionCatalog()))->seed($adapter, $now ?? new DateTimeImmutable());
    }

    public static function drop(PDO|PdoAdapter $connection): void
    {
        $adapter = $connection instanceof PdoAdapter ? $connection : new PdoAdapter($connection);
        foreach (SqlSchema::dropAll($adapter->dialect()) as $statement) {
            $adapter->exec($statement);
        }
    }
}
