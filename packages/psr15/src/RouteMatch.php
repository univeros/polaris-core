<?php

declare(strict_types=1);

namespace Polaris\Psr15;

use Polaris\Http\Manifest\EndpointSpec;

final readonly class RouteMatch
{
    /**
     * @param array<string, string> $params
     * @param list<string> $allowedMethods
     */
    private function __construct(
        public ?EndpointSpec $spec,
        public array $params,
        public array $allowedMethods,
    ) {
    }

    /**
     * @param array<string, string> $params
     */
    public static function found(EndpointSpec $spec, array $params): self
    {
        return new self($spec, $params, []);
    }

    public static function notFound(): self
    {
        return new self(null, [], []);
    }

    /**
     * @param list<string> $allowed
     */
    public static function methodNotAllowed(array $allowed): self
    {
        return new self(null, [], $allowed);
    }
}
