<?php

declare(strict_types=1);

namespace Polaris\Laravel\Schema;

use DateTimeImmutable;
use PDO;
use Polaris\Pdo\SchemaInstaller;

/**
 * What the generated migration calls: {@see SchemaInstaller} on the connection's PDO handle (the
 * tables from the SQL exporter for its dialect, then the permission catalog and the system roles).
 */
final class PolarisSchema
{
    public static function create(PDO $pdo, ?DateTimeImmutable $now = null): void
    {
        SchemaInstaller::create($pdo, $now);
    }

    public static function drop(PDO $pdo): void
    {
        SchemaInstaller::drop($pdo);
    }
}
