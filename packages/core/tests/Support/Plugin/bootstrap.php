<?php

declare(strict_types=1);

/*
 * A `--bootstrap` file for the CLI tests: the application's Config with the sample plugin, on the
 * in-memory adapter (the schema commands take the database from --dsn, not from here).
 */

use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Tests\Support\Plugin\SamplePlugin;
use Polaris\Tests\Support\TestKeys;
use Polaris\Wiring\Config;

$keys = TestKeys::rsa();

return new Config(
    secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('k', 32), 'AUTH_JWT_PRIVATE_KEY' => $keys['private'], 'AUTH_JWT_PUBLIC_KEY' => $keys['public'], 'AUTH_JWT_KID' => 'test']),
    auth: AuthConfig::fromArray(['issuer' => 'https://issuer.test']),
    database: new InMemoryAdapter(),
    plugins: [new SamplePlugin()],
);
