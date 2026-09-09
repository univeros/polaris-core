<?php

declare(strict_types=1);

namespace Polaris\Http\Manifest;

use function array_values;

/**
 * Every endpoint Polaris exposes, as declared in `api/`. The router after WP5.
 */
final class Manifest
{
    /** @var array<string, EndpointSpec> keyed by "METHOD /path" */
    private array $byRoute = [];

    /**
     * @param list<EndpointSpec> $endpoints
     */
    public function __construct(array $endpoints)
    {
        foreach ($endpoints as $endpoint) {
            $this->byRoute[$endpoint->route()] = $endpoint;
        }
    }

    /**
     * @return list<EndpointSpec>
     */
    public function endpoints(): array
    {
        return array_values($this->byRoute);
    }

    public function find(string $method, string $path): ?EndpointSpec
    {
        return $this->byRoute[strtoupper($method) . ' ' . $path] ?? null;
    }
}
