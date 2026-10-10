<?php

declare(strict_types=1);

namespace Polaris\Mcp;

use Closure;

/**
 * One MCP tool: its name (`polaris.orgs.members.list`), description, JSON Schemas and the call. The call
 * answers what the HTTP route would: the status and the decoded body, which the server returns as
 * `structuredContent` (`isError` for a 4xx or 5xx).
 */
final readonly class Tool
{
    /** @var Closure(array<string, mixed>): array{status: int, body: mixed} */
    public Closure $call;

    /**
     * @param array<string, mixed> $inputSchema
     * @param array<string, mixed>|null $outputSchema
     * @param callable(array<string, mixed>): array{status: int, body: mixed} $call
     */
    public function __construct(
        public string $name,
        public string $description,
        public array $inputSchema,
        callable $call,
        public ?array $outputSchema = null,
        public bool $readOnly = false,
        public bool $destructive = false,
    ) {
        $this->call = $call(...);
    }
}
