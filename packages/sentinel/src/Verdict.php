<?php

declare(strict_types=1);

namespace Polaris\Sentinel;

/**
 * One signal's opinion: a score (0 is silence; negative clears the attempt, as an IP allow rule does),
 * its reasons, and whether it proves the caller passed a challenge (a valid captcha token).
 */
final readonly class Verdict
{
    /**
     * @param list<string> $reasons
     */
    public function __construct(public string $signal, public int $score, public array $reasons = [], public bool $passedChallenge = false)
    {
    }

    public static function silent(string $signal): self
    {
        return new self($signal, 0);
    }
}
