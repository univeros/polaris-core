<?php

declare(strict_types=1);

namespace Polaris\Maintenance;

use DateInterval;
use Polaris\Contract\Condition;
use Polaris\Contract\DatabaseAdapter;
use Polaris\Model\EmailVerification;
use Polaris\Model\OtpChallenge;
use Polaris\Model\PasswordReset;
use Polaris\Model\RefreshToken;
use Polaris\Schema\Schema;
use Psr\Clock\ClockInterface;

/**
 * Deletes rows that can no longer be used: consumed or expired one-time challenges, and refresh
 * tokens whose expiry or revocation is older than the grace period that reuse detection needs.
 */
final class PruneExpiredService
{
    public const string DEFAULT_REFRESH_GRACE = 'P7D';

    public function __construct(
        private readonly DatabaseAdapter $database,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * @return array<string, int> deleted rows per table
     */
    public function prune(?DateInterval $refreshGrace = null): array
    {
        $now = $this->clock->now();
        $refreshCutoff = $now->sub($refreshGrace ?? new DateInterval(self::DEFAULT_REFRESH_GRACE));

        $deleted = [];
        foreach ([OtpChallenge::class, EmailVerification::class, PasswordReset::class] as $model) {
            $table = Schema::for($model)->table;
            $deleted[$table] = $this->database->delete($table, ['consumed_at' => Condition::notNull()])
                + $this->database->delete($table, ['expires_at' => Condition::lt($now)]);
        }

        $tokens = Schema::for(RefreshToken::class)->table;
        $deleted[$tokens] = $this->database->delete($tokens, ['expires_at' => Condition::lt($refreshCutoff)])
            + $this->database->delete($tokens, ['revoked_at' => Condition::lt($refreshCutoff)]);

        return $deleted;
    }
}
