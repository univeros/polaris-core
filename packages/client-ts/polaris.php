<?php

declare(strict_types=1);

/*
 * The application the client is generated for: core with the audit, admin, sentinel and sso plugins, so
 * their routes join the OpenAPI document and the client's `audit`, `admin`, `sentinel` and `sso` namespaces. Nothing here is served;
 * the secrets are placeholders the manifest never uses.
 */

use Polaris\Admin\AdminPlugin;
use Polaris\Audit\AuditPlugin;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Sentinel\SentinelPlugin;
use Polaris\Sso\SsoPlugin;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Wiring\Config;

return new Config(
    secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('0', 32), 'AUTH_JWT_PRIVATE_KEY' => 'unused', 'AUTH_JWT_PUBLIC_KEY' => 'unused', 'AUTH_JWT_KID' => 'unused']),
    auth: AuthConfig::fromArray(['issuer' => 'https://polaris.example']),
    database: new InMemoryAdapter(),
    plugins: [new AuditPlugin(), new AdminPlugin(), new SentinelPlugin(), new SsoPlugin(baseUrl: 'https://polaris.example')],
);
