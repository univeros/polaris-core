<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Provider;

/**
 * Verifies a challenge token the client obtained from a captcha (Turnstile, hCaptcha).
 */
interface BotVerifier
{
    public function verify(string $token, ?string $ip): bool;
}
