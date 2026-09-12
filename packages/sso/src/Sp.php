<?php

declare(strict_types=1);

namespace Polaris\Sso;

use SensitiveParameter;

use function rtrim;

/**
 * The service provider side: the URLs a provider's IdP talks to, derived from the application's base
 * URL (where Polaris is mounted, prefix included), and the optional key pair for signed requests and
 * encrypted assertions.
 */
final readonly class Sp
{
    public string $baseUrl;

    public function __construct(string $baseUrl, public ?string $certificate = null, #[SensitiveParameter] public ?string $privateKey = null)
    {
        $this->baseUrl = rtrim($baseUrl, '/');
    }

    public function entityId(string $providerId): string
    {
        return $this->metadataUrl($providerId);
    }

    public function metadataUrl(string $providerId): string
    {
        return $this->baseUrl . '/sso/metadata/' . $providerId;
    }

    public function acsUrl(string $providerId): string
    {
        return $this->baseUrl . '/sso/callback/' . $providerId;
    }

    public function sloUrl(string $providerId): string
    {
        return $this->baseUrl . '/sso/slo/' . $providerId;
    }
}
