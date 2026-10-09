<?php

declare(strict_types=1);

namespace Polaris\Social;

use LogicException;
use Override;
use Polaris\Audit\AuditPlugin;
use Polaris\Audit\Catalog;
use Polaris\Event\UserDeleted;
use Polaris\Plugin\AbstractPlugin;
use Polaris\Social\Provider\Http;
use Polaris\Wiring\Graph;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

use function dirname;

/**
 * The social plugin: `new SocialPlugin(baseUrl: 'https://app.example.com/auth', providers: ['google' =>
 * ['client_id' => ..., 'client_secret' => ...], ...], httpClient: ..., requestFactory: ..., streamFactory:
 * ..., redirectUris: ['https://app.example.com/signed-in'])` in `Config::$plugins`, after `AuditPlugin`.
 * OAuth 2.0 / OpenID Connect sign-in and sign-up through the catalog's providers or any other server,
 * account linking under a policy, Google One Tap, provider tokens on the user's behalf, and an OAuth
 * proxy for preview origins. `baseUrl` is where Polaris is mounted, prefix included: the callbacks the
 * providers are configured with derive from it.
 */
final class SocialPlugin extends AbstractPlugin
{
    public const string ID = 'social';

    /** The sign-in routes for sentinel's `routes` option (path => attempt kind). */
    public const array SENTINEL_ROUTES = ['/social/{provider}/start' => 'sign_in', '/social/google/one-tap' => 'sign_in'];

    private readonly Settings $settings;

    /**
     * @param array<string, array<string, mixed>> $providers provider id => its configuration ({@see Providers})
     * @param list<string> $redirectUris exact application URLs a sign-in may end on; the first is the default
     * @param list<string> $trustedProviders providers whose verified email links to an existing user by itself
     * @param list<string> $allowDifferentEmails providers that may be linked from a session with another email
     * @param string|null $proxy the stable origin registered at the providers, when this deployment is a preview
     */
    public function __construct(
        string $baseUrl,
        private readonly array $providers,
        private readonly ?ClientInterface $httpClient = null,
        private readonly ?RequestFactoryInterface $requestFactory = null,
        private readonly ?StreamFactoryInterface $streamFactory = null,
        array $redirectUris = [],
        array $trustedProviders = ['google', 'apple'],
        array $allowDifferentEmails = [],
        bool $signUp = true,
        bool $respectMfa = true,
        ?string $proxy = null,
    ) {
        $this->settings = new Settings($baseUrl, $redirectUris, $trustedProviders, $allowDifferentEmails, $signUp, $respectMfa, $proxy);
    }

    public static function of(Graph $graph): self
    {
        $plugin = $graph->plugin(self::ID);
        if (!$plugin instanceof self) {
            throw new LogicException('The social plugin is not registered.');
        }

        return $plugin;
    }

    public function settings(): Settings
    {
        return $this->settings;
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
            Http::class => fn(): Http => $this->httpClient !== null && $this->requestFactory !== null && $this->streamFactory !== null
                ? new Http($this->httpClient, $this->requestFactory, $this->streamFactory)
                : throw new LogicException('The social plugin needs a PSR-18 client and PSR-17 request and stream factories to talk to the providers.'),
            Providers::class => fn(Graph $graph): Providers => new Providers($this->providers, $graph->get(Http::class), $graph->cache(), $graph->clock()),
            Accounts::class => static fn(Graph $graph): Accounts => new Accounts($graph->database(), $graph->encrypter(), $graph->clock()),
            Sessions::class => fn(Graph $graph): Sessions => new Sessions($this->settings, $graph->config()->auth, $graph->users(), $graph->unitOfWork(), $graph->sessions(), $graph->tokens(), $graph->principals(), $graph->mfaLogin(), $graph->events(), $graph->clock()),
            SocialService::class => fn(Graph $graph): SocialService => new SocialService(
                $this->settings,
                $graph->get(Providers::class),
                $graph->get(Accounts::class),
                $graph->get(Sessions::class),
                $graph->cache(),
                $graph->pepper(),
                $graph->events(),
                $graph->clock(),
            ),
        ];
    }

    #[Override]
    public function listeners(Graph $graph): array
    {
        self::catalog($graph);

        // An erased user leaves no provider account (its email, profile and tokens) behind.
        return [static function (object $event) use ($graph): void {
            if ($event instanceof UserDeleted) {
                $graph->get(Accounts::class)->unlinkAll($event->userId);
            }
        }];
    }

    /**
     * The `social.*` names join the audit catalog: the audit plugin must be registered.
     */
    public static function catalog(Graph $graph): Catalog
    {
        AuditPlugin::of($graph);
        $catalog = $graph->get(Catalog::class);
        $catalog->extend(AuditNames::ALL);

        return $catalog;
    }
}
