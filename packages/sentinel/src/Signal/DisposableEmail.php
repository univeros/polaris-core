<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Signal;

use Override;
use Polaris\Sentinel\Attempt;
use Polaris\Sentinel\Provider\DomainList;
use Polaris\Sentinel\Signal;
use Polaris\Sentinel\Verdict;

use function in_array;
use function strrchr;
use function substr;

/**
 * A sign-up with a disposable mailbox.
 */
final class DisposableEmail implements Signal
{
    public const string NAME = 'disposable_email';

    /**
     * @param list<string> $kinds
     */
    public function __construct(private readonly DomainList $domains, private readonly array $kinds = [Attempt::SIGN_UP], private readonly int $score = 60)
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
        $at = $attempt->email === null ? false : strrchr($attempt->email, '@');
        if ($at === false || !in_array($attempt->kind, $this->kinds, true)) {
            return Verdict::silent(self::NAME);
        }
        $domain = substr($at, 1);

        return $this->domains->contains($domain) ? new Verdict(self::NAME, $this->score, ['disposable domain ' . $domain]) : Verdict::silent(self::NAME);
    }
}
