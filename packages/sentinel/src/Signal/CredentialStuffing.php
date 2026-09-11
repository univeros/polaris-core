<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Signal;

use Override;
use Polaris\Sentinel\Attempt;
use Polaris\Sentinel\CounterStore;
use Polaris\Sentinel\Resettable;
use Polaris\Sentinel\Signal;
use Polaris\Sentinel\Verdict;
use Psr\SimpleCache\CacheInterface;

use function count;
use function hash;
use function in_array;
use function is_array;
use function sprintf;

/**
 * One IP trying many accounts, or failing most of its sign-ins: the distinct emails an address tried
 * in the window (a small set in the cache) and its failures over attempts (the failures counted by the
 * listener from `UserLoginFailed`).
 */
final class CredentialStuffing implements Signal, Resettable
{
    public const string NAME = 'credential_stuffing';
    private const int MAX_TRACKED_EMAILS = 200;

    public function __construct(
        private readonly CounterStore $counters,
        private readonly CacheInterface $cache,
        private readonly int $window = 600,
        private readonly int $distinctEmails = 5,
        private readonly int $minAttempts = 10,
        private readonly float $failureRatio = 0.8,
        private readonly int $score = 60,
    ) {
    }

    #[Override]
    public function name(): string
    {
        return self::NAME;
    }

    #[Override]
    public function evaluate(Attempt $attempt): Verdict
    {
        if ($attempt->kind !== Attempt::SIGN_IN || $attempt->ip === null) {
            return Verdict::silent(self::NAME);
        }
        $score = 0;
        $reasons = [];
        $attempts = $this->counters->increment(self::attemptsKey($attempt->ip), $this->window);
        if ($attempt->email !== null) {
            $distinct = $this->track($attempt->ip, $attempt->email);
            if ($distinct >= $this->distinctEmails) {
                $score += $this->score;
                $reasons[] = sprintf('%d distinct accounts from one address in %d s', $distinct, $this->window);
            }
        }
        $failures = $this->counters->count(self::failuresKey($attempt->ip), $this->window);
        if ($attempts >= $this->minAttempts && $failures / $attempts >= $this->failureRatio) {
            $score += $this->score;
            $reasons[] = sprintf('%d of %d sign-ins from the address failed', $failures, $attempts);
        }

        return new Verdict(self::NAME, $score, $reasons);
    }

    /**
     * Counted by the listener when a sign-in failed.
     */
    public function failed(?string $ip): void
    {
        if ($ip !== null) {
            $this->counters->increment(self::failuresKey($ip), $this->window);
        }
    }

    #[Override]
    public function reset(string $identifier): void
    {
        $this->counters->reset(self::attemptsKey($identifier), $this->window);
        $this->counters->reset(self::failuresKey($identifier), $this->window);
        $this->cache->delete(self::emailsKey($identifier));
    }

    private function track(string $ip, string $email): int
    {
        $key = self::emailsKey($ip);
        $seen = $this->cache->get($key);
        $seen = is_array($seen) ? $seen : [];
        $hash = hash('sha256', $email);
        if (!in_array($hash, $seen, true) && count($seen) < self::MAX_TRACKED_EMAILS) {
            $seen[] = $hash;
            $this->cache->set($key, $seen, $this->window);
        }

        return count($seen);
    }

    private static function attemptsKey(string $ip): string
    {
        return 'stuffing:attempts:' . $ip;
    }

    private static function failuresKey(string $ip): string
    {
        return 'stuffing:failures:' . $ip;
    }

    private static function emailsKey(string $ip): string
    {
        return 'polaris.sentinel.emails.' . hash('xxh128', $ip);
    }
}
