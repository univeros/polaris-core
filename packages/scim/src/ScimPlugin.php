<?php

declare(strict_types=1);

namespace Polaris\Scim;

use LogicException;
use Override;
use Polaris\Audit\AuditPlugin;
use Polaris\Audit\Catalog;
use Polaris\Audit\Recorder;
use Polaris\Plugin\AbstractPlugin;
use Polaris\Scim\Http\ScimMiddleware;
use Polaris\Wiring\Graph;

use function dirname;
use function preg_match;

/**
 * The SCIM plugin: `new ScimPlugin(baseUrl: 'https://app.example.com/auth')` in `Config::$plugins`,
 * after `AuditPlugin`, `AdminPlugin` and `SsoPlugin`. A SCIM 2.0 server per organization at
 * `/scim/v2/{connectionId}`: a directory provisions users (members) and groups (roles) with a
 * connection token the organization creates and rotates itself under `/orgs/{id}/scim`; the operators
 * see every connection under `/admin/scim`. `baseUrl` is where Polaris is mounted, prefix included:
 * the resources' `meta.location` derives from it.
 */
final class ScimPlugin extends AbstractPlugin
{
    public const string ID = 'scim';

    public function __construct(private readonly string $baseUrl)
    {
        if (preg_match('#^https?://[^/]+#', $baseUrl) !== 1) {
            throw new LogicException('baseUrl must be an absolute http(s) URL, where Polaris is mounted.');
        }
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
            Sp::class => fn(): Sp => new Sp($this->baseUrl),
            Connections::class => static fn(Graph $graph): Connections => new Connections($graph->database(), $graph->pepper(), $graph->clock()),
            Resources::class => static fn(Graph $graph): Resources => new Resources($graph->database(), $graph->clock()),
            Users::class => static fn(Graph $graph): Users => new Users($graph->database(), $graph->users(), $graph->unitOfWork(), $graph->userAdmin(), $graph->get(Resources::class), $graph->events(), $graph->clock()),
            Groups::class => static fn(Graph $graph): Groups => new Groups($graph->database(), $graph->unitOfWork(), $graph->get(Resources::class), $graph->clock()),
            ScimAudit::class => static fn(Graph $graph): ScimAudit => new ScimAudit(self::recorder($graph), $graph->clock()),
        ];
    }

    #[Override]
    public function middleware(Graph $graph): array
    {
        self::catalog($graph);

        return [new ScimMiddleware($graph->get(Connections::class))];
    }

    #[Override]
    public function listeners(Graph $graph): array
    {
        self::catalog($graph);

        return [];
    }

    /**
     * The `scim.*` names join the audit catalog: the audit plugin must be registered.
     */
    public static function catalog(Graph $graph): Catalog
    {
        AuditPlugin::of($graph);
        $catalog = $graph->get(Catalog::class);
        $catalog->extend(AuditNames::ALL);

        return $catalog;
    }

    private static function recorder(Graph $graph): Recorder
    {
        self::catalog($graph);

        return $graph->get(Recorder::class);
    }
}
