<?php

declare(strict_types=1);

namespace Polaris\Laravel\Schema;

use DateTimeImmutable;
use PDO;
use Polaris\Authorization\PermissionCatalog;
use Polaris\Authorization\PermissionCatalogSeeder;
use Polaris\Pdo\PdoAdapter;
use Polaris\Pdo\SqlSchema;

/**
 * What the generated migration calls: the Polaris tables from the SQL exporter for the connection's
 * dialect, then the permission catalog and the system roles. One source of DDL, the same `schema:export`
 * emits; `polaris:schema:diff` proves the result.
 */
final class PolarisSchema
{
    public static function create(PDO $pdo, ?DateTimeImmutable $now = null): void
    {
        $adapter = new PdoAdapter($pdo);
        foreach (SqlSchema::createAll($adapter->dialect()) as $statement) {
            $adapter->exec($statement);
        }
        (new PermissionCatalogSeeder(new PermissionCatalog()))->seed($adapter, $now ?? new DateTimeImmutable());
    }

    public static function drop(PDO $pdo): void
    {
        $adapter = new PdoAdapter($pdo);
        foreach (SqlSchema::dropAll($adapter->dialect()) as $statement) {
            $adapter->exec($statement);
        }
    }
}
