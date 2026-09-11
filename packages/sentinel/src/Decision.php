<?php

declare(strict_types=1);

namespace Polaris\Sentinel;

use function array_map;
use function array_merge;

/**
 * The policy's outcome for an attempt: the action (allow, challenge, block), the summed score and the
 * signals that spoke. In observe mode `action` is what would have happened and `enforced` is false.
 */
final readonly class Decision
{
    public const string ALLOW = 'allow';
    public const string CHALLENGE = 'challenge';
    public const string BLOCK = 'block';

    /**
     * @param list<Verdict> $verdicts the signals that scored (positive or negative)
     */
    public function __construct(public string $action, public int $score, public array $verdicts, public bool $enforced)
    {
    }

    /**
     * @return list<string>
     */
    public function signals(): array
    {
        return array_map(static fn(Verdict $verdict): string => $verdict->signal, $this->verdicts);
    }

    /**
     * @return list<string>
     */
    public function reasons(): array
    {
        return array_merge(...array_map(static fn(Verdict $verdict): array => $verdict->reasons, $this->verdicts));
    }
}
