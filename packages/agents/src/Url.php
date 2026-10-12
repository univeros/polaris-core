<?php

declare(strict_types=1);

namespace Polaris\Agents;

use function array_pop;
use function chr;
use function explode;
use function hexdec;
use function implode;
use function is_string;
use function parse_url;
use function preg_match;
use function preg_replace_callback;
use function strtolower;
use function strtoupper;
use function substr;

/**
 * The URL form a capability location and a request are compared in (RFC 3986 §6.2.2 normalisation):
 * lower-case scheme and host, no default port, dot segments resolved, empty segments and a trailing
 * slash dropped, percent-encoded unreserved characters decoded, no query or fragment. Spelled
 * differently, `https://Host.test:443/./a//b/` and `https://host.test/a/%62` are the same location.
 */
final class Url
{
    private function __construct()
    {
    }

    public static function normalize(string $url): string
    {
        $parts = parse_url($url);
        if ($parts === false || !is_string($parts['scheme'] ?? null) || !is_string($parts['host'] ?? null)) {
            return $url;
        }
        $scheme = strtolower($parts['scheme']);
        $port = $parts['port'] ?? null;
        if (($scheme === 'https' && $port === 443) || ($scheme === 'http' && $port === 80)) {
            $port = null;
        }

        return $scheme . '://' . strtolower($parts['host']) . ($port === null ? '' : ':' . $port) . self::path($parts['path'] ?? '');
    }

    /**
     * The normalised URL without its scheme (`host[:port]/path`): what a request is matched against a
     * location by, so a TLS-terminating proxy that hands the application `http://` still lands on the
     * guarded location (and the JWT's `aud` then decides).
     */
    public static function route(string $url): string
    {
        $normalized = self::normalize($url);
        $separator = explode('://', $normalized, 2);

        return $separator[1] ?? $normalized;
    }

    private static function path(string $path): string
    {
        $decoded = (string) preg_replace_callback('/%([0-9A-Fa-f]{2})/', static function (array $match): string {
            $char = chr((int) hexdec($match[1]));

            return preg_match('/^[A-Za-z0-9\-._~]$/', $char) === 1 ? $char : '%' . strtoupper($match[1]);
        }, $path);
        $segments = [];
        foreach (explode('/', $decoded) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }
            if ($segment === '..') {
                array_pop($segments);
                continue;
            }
            $segments[] = $segment;
        }

        return '/' . implode('/', $segments);
    }
}
