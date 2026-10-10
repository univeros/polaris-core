<?php

declare(strict_types=1);

namespace Polaris\Agent;

use InvalidArgumentException;

use function array_filter;
use function is_array;
use function is_string;
use function str_ends_with;
use function strlen;
use function substr;

/**
 * The discovery document, `GET <mount>/.well-known/agent-configuration`: the provider, the issuer, the
 * absolute endpoints, the token endpoint. The mount (where Polaris lives, prefix included) is read off
 * the execute endpoint, so every other route is called under it.
 */
final readonly class Configuration
{
    public string $mount;
    public string $tokenEndpoint;
    /** @var array<string, string> */
    public array $endpoints;

    /**
     * @param array<string, mixed> $document
     */
    public function __construct(public array $document)
    {
        $endpoints = $document['endpoints'] ?? null;
        $execute = is_array($endpoints) ? ($endpoints['execute'] ?? null) : null;
        $token = $document['token_endpoint'] ?? null;
        if (!is_array($endpoints) || !is_string($execute) || !is_string($token) || !str_ends_with($execute, Routes::EXECUTE['path'])) {
            throw new InvalidArgumentException('Not an agent configuration document (endpoints.execute and token_endpoint are required).');
        }
        $this->endpoints = array_filter($endpoints, is_string(...));
        $this->tokenEndpoint = $token;
        $this->mount = substr($execute, 0, strlen($execute) - strlen(Routes::EXECUTE['path']));
    }

    public function providerName(): string
    {
        return is_string($this->document['provider_name'] ?? null) ? $this->document['provider_name'] : '';
    }

    public function issuer(): string
    {
        return is_string($this->document['issuer'] ?? null) ? $this->document['issuer'] : '';
    }

    /** The MCP endpoint, when polaris/mcp is registered on the server. */
    public function mcpEndpoint(): ?string
    {
        return $this->endpoints['mcp'] ?? null;
    }
}
