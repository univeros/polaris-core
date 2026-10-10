<?php

declare(strict_types=1);

namespace Polaris\OAuth;

use LogicException;
use Override;
use Polaris\Audit\AuditPlugin;
use Polaris\Audit\Catalog;
use Polaris\Contract\BearerResolverProvider;
use Polaris\Event\OrganizationDeleted;
use Polaris\Event\UserDeleted;
use Polaris\OAuth\Http\OAuthRequestMiddleware;
use Polaris\Plugin\AbstractPlugin;
use Polaris\Wiring\Graph;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

use function dirname;
use function preg_match;
use function rtrim;

/**
 * The OAuth provider plugin: `new OAuthPlugin(baseUrl: 'https://app.example.com/auth', consentUrl:
 * 'https://app.example.com/consent', deviceUrl: 'https://app.example.com/device')` in
 * `Config::$plugins`, after `AuditPlugin` and `AdminPlugin`. Polaris as an OAuth 2.1 and OpenID Connect
 * provider: authorization code with PKCE, refresh rotation, client credentials, the device flow,
 * backchannel authentication, token exchange, DPoP, dynamic registration (off by default), client ID
 * metadata documents, discovery; the access tokens it issues are accepted on every Polaris route
 * within their scopes (core's bearer-resolver seam). `baseUrl` is where Polaris is mounted, prefix
 * included: the endpoints the metadata documents advertise derive from it.
 */
final class OAuthPlugin extends AbstractPlugin implements BearerResolverProvider
{
    public const string ID = 'oauth';

    private readonly Settings $settings;
    private readonly string $baseUrl;

    /**
     * @param array<string, string> $scopes extra scopes (name => description) beyond the permission catalog
     * @param list<string> $trustedClients client ids whose users are not asked for consent
     * @param 'off'|'optional'|'required' $dpop
     */
    public function __construct(
        string $baseUrl,
        ?string $consentUrl = null,
        ?string $deviceUrl = null,
        private readonly ?ClientInterface $httpClient = null,
        private readonly ?RequestFactoryInterface $requestFactory = null,
        int $accessTokenTtl = 3600,
        int $refreshTokenTtl = 2592000,
        bool $dynamicRegistration = false,
        bool $clientIdMetadata = true,
        string $dpop = Settings::DPOP_OPTIONAL,
        array $scopes = [],
        array $trustedClients = [],
        int $codeTtl = 600,
        int $deviceCodeTtl = 1800,
        int $pollInterval = 5,
        int $cibaTtl = 600,
    ) {
        if (preg_match('~^https?://[^/\s]+~', $baseUrl) !== 1) {
            throw new LogicException('baseUrl must be an absolute http(s) URL, where Polaris is mounted.');
        }
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->settings = new Settings($consentUrl, $deviceUrl, $accessTokenTtl, $refreshTokenTtl, $codeTtl, $deviceCodeTtl, $pollInterval, $cibaTtl, $dynamicRegistration, $clientIdMetadata, $dpop, $scopes, $trustedClients);
    }

    public static function of(Graph $graph): self
    {
        $plugin = $graph->plugin(self::ID);
        if (!$plugin instanceof self) {
            throw new LogicException('The oauth plugin is not registered.');
        }

        return $plugin;
    }

    public function settings(): Settings
    {
        return $this->settings;
    }

    public function baseUrl(): string
    {
        return $this->baseUrl;
    }

    #[Override]
    public function id(): string
    {
        return self::ID;
    }

    #[Override]
    public function schema(): array
    {
        return Schema::models();
    }

    #[Override]
    public static function manifestDirectory(): string
    {
        return dirname(__DIR__) . '/api';
    }

    #[Override]
    public function services(): array
    {
        return [
            Settings::class => fn(): Settings => $this->settings,
            Fetch::class => fn(): Fetch => new Fetch($this->httpClient, $this->requestFactory),
            Jwt::class => static fn(Graph $graph): Jwt => new Jwt($graph->tokenConfiguration(), $graph->config()->secrets, $graph->clock()),
            Scopes::class => fn(Graph $graph): Scopes => new Scopes($graph->permissionCatalog(), $this->settings),
            Dpop::class => static fn(Graph $graph): Dpop => new Dpop($graph->cache(), $graph->clock()),
            Clients::class => fn(Graph $graph): Clients => new Clients($graph->database(), $graph->pepper(), $graph->get(Scopes::class), $this->settings, $graph->get(Fetch::class), $graph->cache(), $graph->clock()),
            Consents::class => static fn(Graph $graph): Consents => new Consents($graph->database(), $graph->clock()),
            Codes::class => fn(Graph $graph): Codes => new Codes($graph->database(), $graph->pepper(), $this->settings, $graph->clock()),
            Tokens::class => fn(Graph $graph): Tokens => new Tokens($graph->database(), $graph->pepper(), $graph->get(Jwt::class), $this->settings, $graph->users(), $graph->clock()),
            Authorization::class => fn(Graph $graph): Authorization => new Authorization($graph->get(Clients::class), $graph->get(Scopes::class), $graph->get(Codes::class), $graph->get(Consents::class), $this->settings, $graph->get(Jwt::class), $graph->cache(), $graph->clock()),
            Devices::class => fn(Graph $graph): Devices => new Devices($graph->database(), $graph->pepper(), $this->settings, $graph->clock()),
            Ciba::class => fn(Graph $graph): Ciba => new Ciba($graph->database(), $graph->users(), $this->settings, $graph->clock()),
            Exchange::class => static fn(Graph $graph): Exchange => new Exchange($graph->get(Jwt::class), $graph->get(Tokens::class), $graph->get(Scopes::class), $graph->tokenParser(), $graph->clock()),
            Discovery::class => fn(Graph $graph): Discovery => new Discovery($this->settings, $graph->get(Scopes::class), $graph->config()->auth, $this->baseUrl),
        ];
    }

    #[Override]
    public function bearerResolvers(Graph $graph): array
    {
        return [new OAuthResolver($graph->get(Jwt::class), $graph->get(Tokens::class), $graph->get(Scopes::class), $graph->get(Dpop::class), $this->settings, $graph->users(), $graph->clock())];
    }

    #[Override]
    public function middleware(Graph $graph): array
    {
        return [new OAuthRequestMiddleware()];
    }

    #[Override]
    public function listeners(Graph $graph): array
    {
        self::catalog($graph);

        // An erased user leaves no consent or token behind; an erased organization no client.
        return [static function (object $event) use ($graph): void {
            if ($event instanceof UserDeleted) {
                $graph->get(Consents::class)->deleteForUser($event->userId);
                $graph->get(Tokens::class)->deleteForUser($event->userId);
            }
            if ($event instanceof OrganizationDeleted) {
                foreach ($graph->get(Clients::class)->forOrganization($event->organizationId) as $client) {
                    $graph->get(Tokens::class)->deleteForClient($client->clientId);
                }
                $graph->get(Clients::class)->deleteForOrganization($event->organizationId);
            }
        }];
    }

    /**
     * The `oauth.*` names join the audit catalog: the audit plugin must be registered.
     */
    public static function catalog(Graph $graph): Catalog
    {
        AuditPlugin::of($graph);
        $catalog = $graph->get(Catalog::class);
        $catalog->extend(AuditNames::ALL);

        return $catalog;
    }
}
