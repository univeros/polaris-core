<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\AdapterConformance;

use PDO;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Contract\Dialect;
use Polaris\Pdo\PdoAdapter;
use Polaris\Pdo\SqlSchema;

#[CoversNothing]
final class SqliteAdapterConformanceTest extends TestCase
{
    use AdapterConformanceTests;

    private PdoAdapter $adapter;

    protected function setUp(): void
    {
        $pdo = new PDO('sqlite::memory:');
        $pdo->exec('PRAGMA foreign_keys = ON');
        $this->adapter = new PdoAdapter($pdo);
        foreach (SqlSchema::createAll(Dialect::Sqlite) as $statement) {
            $this->adapter->exec($statement);
        }
    }

    protected function adapter(): DatabaseAdapter
    {
        return $this->adapter;
    }
}
