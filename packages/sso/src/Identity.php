<?php

declare(strict_types=1);

namespace Polaris\Sso;

use DateTimeImmutable;

/**
 * Who the identity provider asserted: the subject, the email (normalised by the caller), a display
 * name, the raw claims or attributes, and, for SAML, what replay protection and single logout need.
 *
 * @param array<string, mixed> $attributes
 */
final readonly class Identity
{
    /**
     * @param array<string, mixed> $attributes
     */
    public function __construct(
        public string $subject,
        public string $email,
        public ?string $name = null,
        public array $attributes = [],
        public ?string $assertionId = null,
        public ?DateTimeImmutable $notOnOrAfter = null,
        public ?string $sessionIndex = null,
    ) {
    }
}
