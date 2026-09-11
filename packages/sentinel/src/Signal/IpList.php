<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Signal;

use Override;
use Polaris\Sentinel\Attempt;
use Polaris\Sentinel\IpRules;
use Polaris\Sentinel\Model\IpRule;
use Polaris\Sentinel\Signal;
use Polaris\Sentinel\Verdict;

/**
 * The operators' rules: a block rule refuses the address outright, an allow rule clears it of every
 * other signal.
 */
final class IpList implements Signal
{
    public const string NAME = 'ip_list';

    public function __construct(private readonly IpRules $rules)
    {
    }

    #[Override]
    public function name(): string
    {
        return self::NAME;
    }

    #[Override]
    public function evaluate(Attempt $attempt): Verdict
    {
        $rule = $attempt->ip === null ? null : $this->rules->match($attempt->ip);
        if ($rule === null) {
            return Verdict::silent(self::NAME);
        }

        return $rule->action === IpRule::BLOCK
            ? new Verdict(self::NAME, 100, ['address blocked by rule ' . $rule->cidr])
            : new Verdict(self::NAME, -100, ['address allowed by rule ' . $rule->cidr]);
    }
}
