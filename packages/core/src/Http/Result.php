<?php

declare(strict_types=1);

namespace Polaris\Http;

/**
 * What an endpoint returns: a status, a JSON-serialisable body, and response headers.
 */
final class Result
{
    /**
     * @param array<string, mixed> $body
     * @param array<string, string> $headers
     */
    public function __construct(
        public readonly int $status,
        public readonly array $body = [],
        public readonly array $headers = [],
    ) {
    }
}
