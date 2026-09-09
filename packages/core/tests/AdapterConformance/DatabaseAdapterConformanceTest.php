<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\AdapterConformance;

use PHPUnit\Framework\Attributes\CoversNothing;
use Polaris\Contract\DatabaseAdapter;
use Univeros\Polaris\Tests\Persistence\DatabaseTestCase;

/**
 * The conformance suite on the database the environment selects: PostgreSQL on CI, SQLite locally.
 */
#[CoversNothing]
final class DatabaseAdapterConformanceTest extends DatabaseTestCase
{
    use AdapterConformanceTests;

    protected function adapter(): DatabaseAdapter
    {
        return $this->adapter;
    }
}
