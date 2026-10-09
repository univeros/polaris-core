<?php

declare(strict_types=1);

namespace Polaris\Passwordless;

use LogicException;

use function preg_match;
use function rtrim;

/**
 * The plugin's configuration: where Polaris is mounted (the magic link points there), the redirect
 * URIs a magic link may end on, whether an unknown email signs up, whether the MFA gate applies, and
 * the lifetimes.
 */
final readonly class Settings
{
    public string $baseUrl;

    /**
     * @param list<string> $redirectUris exact URLs a magic link may end on; the first is the default
     */
    public function __construct(
        string $baseUrl,
        public array $redirectUris = [],
        public bool $signUp = true,
        public bool $respectMfa = true,
        public int $magicLinkTtl = 900,
        public int $otpTtl = 300,
        public int $otpLength = 6,
        public int $maxAttempts = 5,
        public int $oneTimeTokenTtl = 180,
    ) {
        if (preg_match('#^https?://[^/]+#', $baseUrl) !== 1) {
            throw new LogicException('baseUrl must be an absolute http(s) URL, where Polaris is mounted.');
        }
        if ($otpLength < 6 || $otpLength > 10) {
            throw new LogicException('otpLength must be 6 to 10 digits.');
        }
        $this->baseUrl = rtrim($baseUrl, '/');
    }
}
