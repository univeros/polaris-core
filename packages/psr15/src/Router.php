<?php

declare(strict_types=1);

namespace Polaris\Psr15;

use Polaris\Http\Manifest\EndpointSpec;
use Polaris\Http\Manifest\Manifest;

use function preg_match;
use function preg_quote;
use function preg_split;
use function rtrim;
use function str_starts_with;
use function strlen;
use function strtoupper;
use function substr;

use const PREG_SPLIT_DELIM_CAPTURE;

/**
 * Matches a request against the manifest: `{param}` segments bind to route parameters.
 */
final class Router
{
    /** @var list<array{spec: EndpointSpec, pattern: string}> */
    private array $routes = [];

    public function __construct(Manifest $manifest, private readonly string $prefix = '/')
    {
        foreach ($manifest->endpoints() as $spec) {
            $pattern = '';
            foreach (preg_split('/(\{\w+\})/', $spec->path, -1, PREG_SPLIT_DELIM_CAPTURE) ?: [] as $segment) {
                $pattern .= preg_match('/^\{(\w+)\}$/', $segment, $m) === 1
                    ? '(?P<' . $m[1] . '>[^/]+)'
                    : preg_quote($segment, '#');
            }
            $this->routes[] = ['spec' => $spec, 'pattern' => '#^' . $pattern . '$#'];
        }
    }

    public function match(string $method, string $path): RouteMatch
    {
        $path = $this->strip($path);
        $method = strtoupper($method);
        $allowed = [];
        foreach ($this->routes as ['spec' => $spec, 'pattern' => $pattern]) {
            if (preg_match($pattern, $path, $matches) !== 1) {
                continue;
            }
            if ($spec->method !== $method) {
                $allowed[] = $spec->method;
                continue;
            }
            $params = [];
            foreach ($matches as $key => $value) {
                if (!is_int($key)) {
                    $params[$key] = $value;
                }
            }

            return RouteMatch::found($spec, $params);
        }

        return $allowed === [] ? RouteMatch::notFound() : RouteMatch::methodNotAllowed($allowed);
    }

    private function strip(string $path): string
    {
        $prefix = rtrim($this->prefix, '/');
        if ($prefix !== '' && str_starts_with($path, $prefix)) {
            $path = substr($path, strlen($prefix));
        }

        return $path === '' ? '/' : $path;
    }
}
