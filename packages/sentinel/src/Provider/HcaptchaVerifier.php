<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Provider;

use Override;

final class HcaptchaVerifier extends SiteVerifier
{
    #[Override]
    protected function endpoint(): string
    {
        return 'https://api.hcaptcha.com/siteverify';
    }
}
