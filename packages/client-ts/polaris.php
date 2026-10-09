<?php

declare(strict_types=1);

/*
 * The application the client is generated for: core with the audit, admin, sentinel, sso, scim, messaging,
 * passwordless, username, anonymous and multi-session plugins, so their routes join the OpenAPI document and
 * the client's `audit`, `admin`, `sentinel`, `sso`, `scim`, `passwordless`, `username`, `anonymous` and
 * `multiSession` namespaces. Nothing here is served;
 * the secrets are placeholders the manifest never uses.
 */

use Polaris\Admin\AdminPlugin;
use Polaris\Anonymous\AnonymousPlugin;
use Polaris\Audit\AuditPlugin;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Messaging\MessagingPlugin;
use Polaris\MultiSession\MultiSessionPlugin;
use Polaris\Passwordless\PasswordlessPlugin;
use Polaris\Sentinel\SentinelPlugin;
use Polaris\Scim\ScimPlugin;
use Polaris\Sso\SsoPlugin;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Username\UsernamePlugin;
use Polaris\Wiring\Config;

return new Config(
    secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('0', 32), 'AUTH_JWT_PRIVATE_KEY' => 'unused', 'AUTH_JWT_PUBLIC_KEY' => 'unused', 'AUTH_JWT_KID' => 'unused']),
    auth: AuthConfig::fromArray(['issuer' => 'https://polaris.example']),
    database: new InMemoryAdapter(),
    plugins: [new AuditPlugin(), new AdminPlugin(), new SentinelPlugin(), new SsoPlugin(baseUrl: 'https://polaris.example'), new ScimPlugin(baseUrl: 'https://polaris.example'), new MessagingPlugin(), new PasswordlessPlugin(baseUrl: 'https://polaris.example'), new UsernamePlugin(), new AnonymousPlugin(), new MultiSessionPlugin()],
);
