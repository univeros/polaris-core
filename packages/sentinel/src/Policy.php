<?php

declare(strict_types=1);

namespace Polaris\Sentinel;

use function max;
use function min;

/**
 * Sums the verdicts (capped at 100, floored at 0 after an allow rule) and maps the score to an action:
 * below `challengeAt` allow, from it challenge, from `blockAt` block. A verdict that proves a passed
 * challenge turns a challenge into an allow.
 */
final readonly class Policy
{
    public function __construct(public int $challengeAt = 40, public int $blockAt = 80)
    {
    }

    /**
     * @param list<Verdict> $verdicts
     */
    public function decide(array $verdicts, bool $enforced): Decision
    {
        $score = 0;
        $fired = [];
        $passed = false;
        foreach ($verdicts as $verdict) {
            if ($verdict->score !== 0) {
                $fired[] = $verdict;
            }
            $score += $verdict->score;
            $passed = $passed || $verdict->passedChallenge;
        }
        $score = max(0, min(100, $score));
        $action = match (true) {
            $score >= $this->blockAt => Decision::BLOCK,
            $score >= $this->challengeAt => $passed ? Decision::ALLOW : Decision::CHALLENGE,
            default => Decision::ALLOW,
        };

        return new Decision($action, $score, $fired, $enforced);
    }
}
