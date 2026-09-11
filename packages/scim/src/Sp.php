<?php

declare(strict_types=1);

namespace Polaris\Scim;

use function rtrim;

/**
 * Where the SCIM endpoints live, from the application's base URL (where Polaris is mounted, prefix
 * included): the `meta.location` of every resource.
 */
final readonly class Sp
{
    public string $baseUrl;

    public function __construct(string $baseUrl)
    {
        $this->baseUrl = rtrim($baseUrl, '/');
    }

    public function location(string $connectionId): string
    {
        return $this->baseUrl . '/scim/v2/' . $connectionId;
    }
}
