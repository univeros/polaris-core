<?php

declare(strict_types=1);

namespace Polaris\Agent;

use function array_filter;
use function array_values;
use function ceil;
use function count;
use function max;
use function sleep;
use function time;

/**
 * Polls the agent's session (its grants with their status) every `interval` seconds until every grant
 * of the approval is `active` (they are returned), one is `denied` or `revoked`, `expires_in` has
 * passed or the attempts are spent, or `cancelled()` says so. A 429 or `slow_down` adds five seconds
 * to the interval, as RFC 8628 has it. The clock and the pause are injectable for tests.
 */
final class Approvals
{
    public const int SLOW_DOWN = 5;

    private function __construct()
    {
    }

    /**
     * @param array<string, mixed> $approval as `POST /agents/grants/request` answered it (`id`, `interval`, `expires_in`)
     * @param callable(): list<array<string, mixed>> $poll the agent's grants, now
     * @param (callable(int): void)|null $sleep
     * @param (callable(): int)|null $now
     * @param (callable(): bool)|null $cancelled
     * @return list<array<string, mixed>> the approval's grants, active
     * @throws ApprovalException `denied`, `expired`, `cancelled`
     * @throws AgentException any other refusal of the poll
     */
    public static function wait(array $approval, callable $poll, ?callable $sleep = null, ?callable $now = null, ?int $maxAttempts = null, ?callable $cancelled = null): array
    {
        $sleep ??= static fn(int $seconds): int => sleep($seconds);
        $now ??= static fn(): int => time();
        $interval = max(1, (int) ($approval['interval'] ?? 5));
        $expiresIn = max(1, (int) ($approval['expires_in'] ?? 600));
        $deadline = $now() + $expiresIn;
        $maxAttempts ??= (int) ceil($expiresIn / $interval) + 1;
        for ($attempt = 0; $attempt < $maxAttempts; $attempt++) {
            // The next poll would land after the approval expired: nothing left to wait for.
            if ($now() + $interval > $deadline) {
                break;
            }
            $sleep($interval);
            if ($cancelled !== null && $cancelled()) {
                throw new ApprovalException(ApprovalException::CANCELLED, $approval, 'The wait for the approval was cancelled.');
            }
            try {
                $grants = $poll();
            } catch (AgentException $exception) {
                if ($exception->status === 429 || $exception->error === 'slow_down') {
                    $interval += self::SLOW_DOWN;
                    continue;
                }
                throw $exception;
            }
            $mine = array_values(array_filter($grants, static fn(array $grant): bool => ($grant['approval_id'] ?? null) === ($approval['id'] ?? null)));
            foreach ($mine as $grant) {
                if (($grant['status'] ?? null) === 'denied' || ($grant['status'] ?? null) === 'revoked') {
                    throw new ApprovalException(ApprovalException::DENIED, $approval, 'The approval was denied.');
                }
            }
            if ($mine !== [] && count(array_filter($mine, static fn(array $grant): bool => ($grant['status'] ?? null) === 'active')) === count($mine)) {
                return $mine;
            }
        }
        throw new ApprovalException(ApprovalException::EXPIRED, $approval, 'The approval expired before it was decided.');
    }
}
