<?php

declare(strict_types=1);

namespace Polaris\Pdo;

use DateTimeImmutable;
use PDO;
use Polaris\Authorization\PermissionCatalog;
use Polaris\Authorization\PermissionCatalogSeeder;

/**
 * What a host's migration or console command calls to install Polaris on a connection: the tables
 * from the SQL exporter for the connection's dialect (plugins' included once `Polaris::create()` ran),
 * then the permission catalog and the system roles, as `schema:export` plus the seeder would.
 * `schema:diff` proves the result. `createMissing()` does the same on a database that already holds
 * some of the tables.
 */
final class SchemaInstaller
{
    /**
     * @param PermissionCatalog|null $catalog the graph's catalog, so the plugins' permissions are seeded too
     */
    public static function create(PDO|PdoAdapter $connection, ?DateTimeImmutable $now = null, ?PermissionCatalog $catalog = null): void
    {
        $adapter = $connection instanceof PdoAdapter ? $connection : new PdoAdapter($connection);
        foreach (SqlSchema::createAll($adapter->dialect()) as $statement) {
            $adapter->exec($statement);
        }
        (new PermissionCatalogSeeder($catalog ?? new PermissionCatalog()))->seed($adapter, $now ?? new DateTimeImmutable());
    }

    /**
     * For a database Polaris is already installed on, after a plugin was added: creates only the tables
     * `SchemaInspector` does not find, in foreign-key order, then seeds the permission catalog and the system
     * roles (the seeder is idempotent). A table that exists is left as it is, rows and columns alike;
     * `schema:diff` reports what it lacks.
     *
     * @param PermissionCatalog|null $catalog the graph's catalog, so the plugins' permissions are seeded too
     * @return list<string> the tables created, in the order they were
     */
    public static function createMissing(PDO|PdoAdapter $connection, ?DateTimeImmutable $now = null, ?PermissionCatalog $catalog = null): array
    {
        $adapter = $connection instanceof PdoAdapter ? $connection : new PdoAdapter($connection);
        $inspector = new SchemaInspector($adapter->pdo(), $adapter->dialect());
        $created = [];
        foreach (SqlSchema::ordered() as $model) {
            if ($inspector->table($model->table) !== null) {
                continue;
            }
            foreach (SqlSchema::create($model, $adapter->dialect()) as $statement) {
                $adapter->exec($statement);
            }
            $created[] = $model->table;
        }
        (new PermissionCatalogSeeder($catalog ?? new PermissionCatalog()))->seed($adapter, $now ?? new DateTimeImmutable());

        return $created;
    }

    public static function drop(PDO|PdoAdapter $connection): void
    {
        $adapter = $connection instanceof PdoAdapter ? $connection : new PdoAdapter($connection);
        foreach (SqlSchema::dropAll($adapter->dialect()) as $statement) {
            $adapter->exec($statement);
        }
    }
}
