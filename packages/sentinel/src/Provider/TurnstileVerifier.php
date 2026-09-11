<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Provider;

use Override;

final class TurnstileVerifier extends SiteVerifier
{
    #[Override]
    protected function endpoint(): string
    {
        return 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
    }
}
