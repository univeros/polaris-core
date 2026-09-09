<?php

declare(strict_types=1);

namespace Polaris\Http;

use JsonSerializable;
use Psr\Http\Message\ServerRequestInterface;

use function array_key_exists;
use function array_replace;
use function is_object;
use function json_decode;
use function json_encode;

/**
 * What an endpoint receives: the request data (route parameters, then the parsed body, cookies,
 * query and uploaded files, later sources overriding earlier ones, as the 1.0 framework merged
 * them) and the request attributes adapters set (token, client context, MFA ticket, authority).
 */
final class Input
{
    /**
     * @param array<string, mixed> $data
     * @param array<string, mixed> $attributes
     */
    public function __construct(private readonly array $data = [], private readonly array $attributes = [])
    {
    }

    /**
     * @param array<string, mixed> $routeParams
     */
    public static function fromServerRequest(ServerRequestInterface $request, array $routeParams = []): self
    {
        $data = array_replace(
            $routeParams,
            self::parsedBody($request),
            $request->getCookieParams(),
            $request->getQueryParams(),
            $request->getUploadedFiles(),
        );

        return new self($data, $request->getAttributes());
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return array_key_exists($key, $this->data) ? $this->data[$key] : $default;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->data);
    }

    /**
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->data;
    }

    public function attribute(string $key, mixed $default = null): mixed
    {
        return array_key_exists($key, $this->attributes) ? $this->attributes[$key] : $default;
    }

    /**
     * @return array<string, mixed>
     */
    public function attributes(): array
    {
        return $this->attributes;
    }

    public function withAttribute(string $key, mixed $value): self
    {
        return new self($this->data, [...$this->attributes, $key => $value]);
    }

    /**
     * @return array<string, mixed>
     */
    private static function parsedBody(ServerRequestInterface $request): array
    {
        $body = $request->getParsedBody();
        if ($body === null || $body === []) {
            return [];
        }
        if ($body instanceof JsonSerializable) {
            return (array) $body->jsonSerialize();
        }
        if (is_object($body)) {
            $encoded = json_encode($body);

            return $encoded === false ? [] : (array) json_decode($encoded, true);
        }

        return $body;
    }
}
