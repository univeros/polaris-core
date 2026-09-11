<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Provider;

use Override;

/**
 * No captcha: every token fails, so the bot signal never clears a challenge.
 */
final class NullVerifier implements BotVerifier
{
    #[Override]
    public function verify(string $token, ?string $ip): bool
    {
        return false;
    }
}
