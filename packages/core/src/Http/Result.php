<?php

declare(strict_types=1);

namespace Polaris\Http;

/**
 * What an endpoint returns: a status, a JSON-serialisable body (or a raw one), and response headers.
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
        /** An RFC 9457 problem document (`application/problem+json`) rather than a plain JSON body. */
        public readonly bool $problem = false,
        /** A body sent as is (SAML metadata XML, for instance) with the Content-Type of `$headers`; `$body` is then ignored. */
        public readonly ?string $raw = null,
    ) {
    }
}
