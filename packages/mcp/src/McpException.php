<?php

declare(strict_types=1);

namespace Polaris\Mcp;

use Polaris\Http\Endpoint;
use RuntimeException;

use function str_replace;
use function ucwords;

/**
 * A refused MCP request: `$name` is the problem type `mcp/<name>`, `$status` the HTTP status,
 * `$headers` what the response must carry (`WWW-Authenticate`), `$extensions` the problem document's
 * further members (`missing_scopes`). {@see problem()} is the RFC 9457 document in the plugins' shape.
 */
final class McpException extends RuntimeException
{
    public const string UNAUTHORIZED = 'unauthorized';
    public const string INSUFFICIENT_SCOPE = 'insufficient_scope';
    public const string LEGACY_PROTOCOL = 'legacy_protocol';

    /**
     * @param array<string, string> $headers
     * @param array<string, mixed> $extensions
     */
    public function __construct(
        public readonly string $name,
        public readonly string $detail,
        public readonly int $status,
        public readonly array $headers = [],
        public readonly array $extensions = [],
    ) {
        parent::__construct($name . ': ' . $detail);
    }

    /**
     * @return array<string, mixed>
     */
    public function problem(): array
    {
        return [
            'type' => Endpoint::PROBLEM_TYPES . 'mcp/' . $this->name,
            'title' => ucwords(str_replace('_', ' ', $this->name)),
            'status' => $this->status,
            'detail' => $this->detail,
            'error' => 'mcp_' . $this->name,
            'message' => $this->detail,
            ...$this->extensions,
        ];
    }
}
