<?php

declare(strict_types=1);

/*
 * The application the client is generated for: core with the audit, admin, sentinel, sso, scim, messaging,
 * passwordless, username, anonymous, multi-session, social, passkey, api-keys and oauth plugins, so their routes
 * join the OpenAPI document and the client's `audit`, `admin`, `sentinel`, `sso`, `scim`, `passwordless`,
 * `username`, `anonymous`, `multiSession`, `social`, `passkey`, `apiKeys` and `oauth` namespaces. Nothing here is served;
 * the secrets are placeholders the manifest never uses.
 */

use Polaris\Admin\AdminPlugin;
use Polaris\ApiKeys\ApiKeysPlugin;
use Polaris\Anonymous\AnonymousPlugin;
use Polaris\Audit\AuditPlugin;
use Polaris\Config\AuthConfig;
use Polaris\Config\Secrets;
use Polaris\Messaging\MessagingPlugin;
use Polaris\Passkey\PasskeyPlugin;
use Polaris\MultiSession\MultiSessionPlugin;
use Polaris\OAuth\OAuthPlugin;
use Polaris\Passwordless\PasswordlessPlugin;
use Polaris\Sentinel\SentinelPlugin;
use Polaris\Social\SocialPlugin;
use Polaris\Scim\ScimPlugin;
use Polaris\Sso\SsoPlugin;
use Polaris\Testing\InMemoryAdapter;
use Polaris\Username\UsernamePlugin;
use Polaris\Wiring\Config;

return new Config(
    secrets: Secrets::fromEnvironment(['APP_KEY' => str_repeat('0', 32), 'AUTH_JWT_PRIVATE_KEY' => 'unused', 'AUTH_JWT_PUBLIC_KEY' => 'unused', 'AUTH_JWT_KID' => 'unused']),
    auth: AuthConfig::fromArray(['issuer' => 'https://polaris.example']),
    database: new InMemoryAdapter(),
    plugins: [new AuditPlugin(), new AdminPlugin(), new SentinelPlugin(), new SsoPlugin(baseUrl: 'https://polaris.example'), new ScimPlugin(baseUrl: 'https://polaris.example'), new MessagingPlugin(), new PasswordlessPlugin(baseUrl: 'https://polaris.example'), new UsernamePlugin(), new AnonymousPlugin(), new MultiSessionPlugin(), new SocialPlugin(baseUrl: 'https://polaris.example', providers: []), new PasskeyPlugin(origins: ['https://polaris.example']), new ApiKeysPlugin(), new OAuthPlugin(baseUrl: 'https://polaris.example', consentUrl: 'https://polaris.example/consent', deviceUrl: 'https://polaris.example/device', dynamicRegistration: true)],
);
