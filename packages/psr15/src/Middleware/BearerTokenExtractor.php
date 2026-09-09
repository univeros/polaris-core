<?php

declare(strict_types=1);

namespace Polaris\Psr15\Middleware;

use Psr\Http\Message\ServerRequestInterface;

use function preg_match;
use function trim;

final class BearerTokenExtractor
{
    public function __construct(private readonly string $header = 'Authorization')
    {
    }

    public function extract(ServerRequestInterface $request): ?string
    {
        $value = $request->getHeader($this->header)[0] ?? '';
        if (preg_match('/^Bearer\s+(\S.*)$/i', $value, $matches) !== 1) {
            return null;
        }

        return trim($matches[1]);
    }
}
