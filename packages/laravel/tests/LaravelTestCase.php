<?php

declare(strict_types=1);

namespace Polaris\Laravel\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Tests that boot a Laravel application through {@see LaravelApp} start from a clean process.
 */
abstract class LaravelTestCase extends TestCase
{
    protected function tearDown(): void
    {
        LaravelApp::reset();
        parent::tearDown();
    }
}
