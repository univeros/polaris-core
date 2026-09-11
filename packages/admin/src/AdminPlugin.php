<?php

declare(strict_types=1);

namespace Polaris\Admin;

use Override;
use Polaris\Admin\Console\GrantCommand;
use Polaris\Admin\Console\KeyCommand;
use Polaris\Admin\Http\AdminMiddleware;
use Polaris\Admin\Principal\Principals;
use Polaris\Audit\Activity\ActivityTracker;
use Polaris\Audit\AuditPlugin;
use Polaris\Audit\Catalog;
use Polaris\Audit\Recorder;
use Polaris\Cli\CommandProvider;
use Polaris\Plugin\AbstractPlugin;
use Polaris\Repository\MembershipRepository;
use Polaris\Repository\MembershipRoleRepository;
use Polaris\Repository\OrganizationRepository;
use Polaris\Repository\RoleRepository;
use Polaris\Wiring\Graph;

use function dirname;

/**
 * The admin plugin: `new AdminPlugin()` in `Config::$plugins`, after `AuditPlugin` (every admin
 * action is recorded through it). Admin users (a grant, or the superadmin role) and API keys call
 * the routes under `/admin`; the middleware resolves the principal, the endpoints check the role
 * matrix; `admin:key` and `admin:grant` create the first principals.
 */
final class AdminPlugin extends AbstractPlugin implements CommandProvider
{
    public const string ID = 'admin';

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
            Grants::class => static fn(Graph $graph): Grants => new Grants($graph->database(), $graph->identities(), $graph->unitOfWork(), $graph->clock()),
            Keys::class => static fn(Graph $graph): Keys => new Keys($graph->database(), $graph->identities(), $graph->unitOfWork(), $graph->pepper(), $graph->clock()),
            Principals::class => static fn(Graph $graph): Principals => new Principals($graph->get(Grants::class), $graph->get(Keys::class), $graph->tokenFactory(), $graph->users(), $graph->permissionResolver()),
            AdminAudit::class => static fn(Graph $graph): AdminAudit => new AdminAudit(self::recorder($graph), $graph->clock()),
            Users::class => static fn(Graph $graph): Users => new Users(
                $graph->database(),
                $graph->users(),
                $graph->userAdmin(),
                $graph->passwordHasher(),
                $graph->passwordPolicy(),
                $graph->sessions(),
                $graph->unitOfWork(),
                $graph->get(ActivityTracker::class),
                $graph->clock(),
                $graph->events(),
            ),
            Impersonation::class => static fn(Graph $graph): Impersonation => new Impersonation($graph->tokens(), $graph->principals(), $graph->users(), $graph->config()->auth, $graph->clock()),
            Organizations::class => static fn(Graph $graph): Organizations => new Organizations(
                $graph->database(),
                new OrganizationRepository($graph->database(), $graph->identities()),
                new MembershipRepository($graph->database(), $graph->identities()),
                new MembershipRoleRepository($graph->database(), $graph->identities()),
                new RoleRepository($graph->database(), $graph->identities()),
                $graph->memberships(),
                $graph->organizations(),
                $graph->unitOfWork(),
                $graph->events(),
            ),
            Stats::class => static fn(Graph $graph): Stats => new Stats($graph->database(), $graph->clock()),
        ];
    }

    #[Override]
    public function middleware(Graph $graph): array
    {
        self::catalog($graph);

        return [new AdminMiddleware($graph->get(Principals::class))];
    }

    #[Override]
    public function commands(Graph $graph): array
    {
        return [new KeyCommand(static fn(): Graph => $graph), new GrantCommand(static fn(): Graph => $graph)];
    }

    /**
     * The audit catalog with the `admin.*` names: the audit plugin must be registered.
     */
    private static function catalog(Graph $graph): Catalog
    {
        AuditPlugin::of($graph);
        $catalog = $graph->get(Catalog::class);
        $catalog->extend(AdminAudit::NAMES);

        return $catalog;
    }

    private static function recorder(Graph $graph): Recorder
    {
        self::catalog($graph);

        return $graph->get(Recorder::class);
    }
}
