<?php

declare(strict_types=1);

namespace Polaris\Sso\Tests\Support;

use Override;
use Polaris\Sso\Domain\DomainVerifier;

/**
 * Verifies the domains listed here, by DNS.
 */
final class FakeVerifier implements DomainVerifier
{
    /** @var list<string> */
    public static array $verifiable = [];

    #[Override]
    public function verify(string $domain, string $token): ?string
    {
        return in_array($domain, self::$verifiable, true) ? 'dns' : null;
    }
}
