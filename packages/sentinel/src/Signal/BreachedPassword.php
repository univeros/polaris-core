<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Signal;

use Override;
use Polaris\Sentinel\Attempt;
use Polaris\Sentinel\Provider\BreachChecker;
use Polaris\Sentinel\Signal;
use Polaris\Sentinel\Verdict;

use function in_array;

/**
 * A new password that appears in a breach corpus (sign-up, password reset).
 */
final class BreachedPassword implements Signal
{
    public const string NAME = 'breached_password';

    /**
     * @param list<string> $kinds
     */
    public function __construct(private readonly BreachChecker $checker, private readonly array $kinds = [Attempt::SIGN_UP, Attempt::PASSWORD_RESET], private readonly int $score = 50)
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
        if ($attempt->password === null || $attempt->password === '' || !in_array($attempt->kind, $this->kinds, true)) {
            return Verdict::silent(self::NAME);
        }

        return $this->checker->isBreached($attempt->password) ? new Verdict(self::NAME, $this->score, ['password found in a breach']) : Verdict::silent(self::NAME);
    }
}
