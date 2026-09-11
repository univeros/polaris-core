<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Signal;

use Override;
use Polaris\Sentinel\Attempt;
use Polaris\Sentinel\Provider\BotVerifier;
use Polaris\Sentinel\Signal;
use Polaris\Sentinel\Verdict;

/**
 * A captcha token in the request (`captcha_token`): verified, it proves a challenge was passed;
 * invalid, it is a bot's guess; absent, the signal is silent.
 */
final class Bot implements Signal
{
    public const string NAME = 'bot';

    public function __construct(private readonly BotVerifier $verifier, private readonly int $score = 80)
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
        if ($attempt->captchaToken === null || $attempt->captchaToken === '') {
            return Verdict::silent(self::NAME);
        }
        if ($this->verifier->verify($attempt->captchaToken, $attempt->ip)) {
            return new Verdict(self::NAME, 0, ['captcha passed'], passedChallenge: true);
        }

        return new Verdict(self::NAME, $this->score, ['captcha token invalid']);
    }
}
