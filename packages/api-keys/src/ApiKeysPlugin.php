<?php

declare(strict_types=1);

namespace Polaris\ApiKeys;

use LogicException;
use Override;
use Polaris\ApiKeys\Http\ApiKeyMiddleware;
use Polaris\ApiKeys\Http\ApiKeyResolver;
use Polaris\ApiKeys\Http\Responses;
use Polaris\Audit\AuditPlugin;
use Polaris\Audit\Catalog;
use Polaris\Contract\BearerResolverProvider;
use Polaris\Event\OrganizationDeleted;
use Polaris\Event\UserDeleted;
use Polaris\Plugin\AbstractPlugin;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ResponseFactoryInterface;

use function dirname;

/**
 * The API-keys plugin: `new ApiKeysPlugin()` in `Config::$plugins`, after `AuditPlugin`. Keys owned by
 * users and by organizations (`pk_live_...`, `pk_test_...`), each with a subset of its owner's
 * permissions, an optional rate limit, an expiry, rotation with a grace window and revocation;
 * presented as `Authorization: Bearer pk_...` or `x-api-key`, a key authenticates every Polaris route
 * as its owner with the delegated permissions (core's bearer-resolver seam), except the step-up ones.
 */
final class ApiKeysPlugin extends AbstractPlugin implements BearerResolverProvider
{
    public const string ID = 'api-keys';

    private readonly Settings $settings;

    /**
     * @param 'live'|'test' $environment the prefix of keys created without one
     * @param int $rotationGrace seconds a rotated key's predecessor stays valid
     * @param int $maxPerOwner live keys an owner may hold
     */
    public function __construct(
        string $environment = Settings::LIVE,
        int $rotationGrace = 86400,
        int $maxPerOwner = 50,
        private readonly ?ResponseFactoryInterface $responses = null,
    ) {
        $this->settings = new Settings($environment, $rotationGrace, $maxPerOwner);
    }

    public static function of(Graph $graph): self
    {
        $plugin = $graph->plugin(self::ID);
        if (!$plugin instanceof self) {
            throw new LogicException('The api-keys plugin is not registered.');
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
            Keys::class => fn(Graph $graph): Keys => new Keys($graph->database(), $graph->pepper(), $graph->permissionCatalog(), $this->settings, $graph->clock()),
        ];
    }

    #[Override]
    public function bearerResolvers(Graph $graph): array
    {
        return [new ApiKeyResolver($graph->get(Keys::class), $graph->users(), $graph->clock())];
    }

    #[Override]
    public function middleware(Graph $graph): array
    {
        return [new ApiKeyMiddleware($graph->rateStore(), $graph->clock(), $this->responses ?? $graph->config()->responseFactory ?? Responses::discover())];
    }

    #[Override]
    public function listeners(Graph $graph): array
    {
        self::catalog($graph);

        // An erased user or organization leaves no key behind.
        return [static function (object $event) use ($graph): void {
            if ($event instanceof UserDeleted) {
                $graph->get(Keys::class)->deleteForUser($event->userId);
            }
            if ($event instanceof OrganizationDeleted) {
                $graph->get(Keys::class)->deleteForOrganization($event->organizationId);
            }
        }];
    }

    /**
     * The `api_keys.*` names join the audit catalog: the audit plugin must be registered.
     */
    public static function catalog(Graph $graph): Catalog
    {
        AuditPlugin::of($graph);
        $catalog = $graph->get(Catalog::class);
        $catalog->extend(AuditNames::ALL);

        return $catalog;
    }
}
