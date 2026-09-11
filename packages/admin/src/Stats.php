<?php

declare(strict_types=1);

namespace Polaris\Admin;

use DateInterval;
use Polaris\Audit\Catalog;
use Polaris\Audit\Schema as Audit;
use Polaris\Contract\Condition;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Model\Organization;
use Polaris\Model\RefreshToken;
use Polaris\Model\User;
use Polaris\Schema\Schema as Registry;
use Psr\Clock\ClockInterface;

use const DATE_ATOM;

/**
 * The instance at a glance: totals, and sign-ups, sign-ins and active users over the last day, week
 * and month, counted from the audit tables.
 */
final class Stats
{
    private const array WINDOWS = ['24h' => 'PT24H', '7d' => 'P7D', '30d' => 'P30D'];

    public function __construct(private readonly DatabaseAdapter $database, private readonly ClockInterface $clock)
    {
    }

    /**
     * @return array<string, mixed>
     */
    public function snapshot(): array
    {
        $now = $this->clock->now();
        $since = [];
        foreach (self::WINDOWS as $window => $interval) {
            $since[$window] = $now->sub(new DateInterval($interval));
        }
        $count = fn(string $table, string $column, string $window, array $criteria = []): int
            => $this->database->count($table, [...$criteria, $column => Condition::gte($since[$window])]);
        $series = static function (callable $of): array {
            $out = [];
            foreach (self::WINDOWS as $window => $interval) {
                $out[$window] = $of($window);
            }

            return $out;
        };

        return [
            'generated_at' => $now->format(DATE_ATOM),
            'totals' => [
                'users' => $this->database->count(Registry::for(User::class)->table, []),
                'organizations' => $this->database->count(Registry::for(Organization::class)->table, ['status' => Organization::STATUS_ACTIVE]),
                'active_sessions' => $this->database->count(Registry::for(RefreshToken::class)->table, ['revoked_at' => null, 'expires_at' => Condition::gt($now)]),
            ],
            'sign_ups' => $series(static fn(string $window): int => $count(Audit::EVENTS, 'occurred_at', $window, ['name' => Catalog::USER_SIGNED_UP])),
            'sign_ins' => $series(static fn(string $window): int => $count(Audit::EVENTS, 'occurred_at', $window, ['name' => Catalog::SESSION_SIGNED_IN])),
            'active_users' => $series(static fn(string $window): int => $count(Audit::ACTIVITY, 'last_active_at', $window)),
        ];
    }
}
