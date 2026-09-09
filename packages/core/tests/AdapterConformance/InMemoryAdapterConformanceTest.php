<?php

declare(strict_types=1);

namespace Univeros\Polaris\Tests\AdapterConformance;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Testing\InMemoryAdapter;

#[CoversNothing]
final class InMemoryAdapterConformanceTest extends TestCase
{
    use AdapterConformanceTests;

    private InMemoryAdapter $adapter;

    protected function setUp(): void
    {
        $this->adapter = new InMemoryAdapter();
    }

    protected function adapter(): DatabaseAdapter
    {
        return $this->adapter;
    }
}
