<?php

declare(strict_types=1);

namespace Polaris\Sentinel;

/**
 * One local heuristic. Evaluation may count the attempt (velocity does); it never blocks by itself.
 */
interface Signal
{
    public function name(): string;

    public function evaluate(Attempt $attempt): Verdict;
}
