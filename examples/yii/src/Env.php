<?php

declare(strict_types=1);

namespace PolarisDemo;

use RuntimeException;

use function file_get_contents;
use function getenv;
use function is_file;
use function preg_match;
use function putenv;
use function str_ends_with;
use function substr;
use function trim;

/**
 * Loads `.env` (KEY=value lines, `#` comments) into the environment and resolves `*_FILE`
 * variables to the file contents, so PEM keys live in files rather than in one-line strings.
 */
final class Env
{
    public static function load(string $root): void
    {
        $file = $root . '/.env';
        if (is_file($file)) {
            foreach (explode("\n", (string) file_get_contents($file)) as $line) {
                if (preg_match('/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/', $line, $m) === 1 && getenv($m[1]) === false) {
                    putenv($m[1] . '=' . trim($m[2], '"\''));
                }
            }
        }
        foreach (['AUTH_JWT_PRIVATE_KEY', 'AUTH_JWT_PUBLIC_KEY'] as $key) {
            $path = getenv($key . '_FILE');
            if ($path !== false && $path !== '' && getenv($key) === false) {
                $absolute = str_starts_with($path, '/') ? $path : $root . '/' . $path;
                if (!is_file($absolute)) {
                    throw new RuntimeException("$key\_FILE points to a missing file: $absolute (run bin/setup)");
                }
                putenv($key . '=' . (string) file_get_contents($absolute));
            }
        }
    }

    public static function require(string $key): string
    {
        $value = getenv($key);
        if ($value === false || $value === '') {
            throw new RuntimeException("$key is not set (copy .env.example to .env or run bin/setup)");
        }

        return $value;
    }

    public static function path(string $root, string $value): string
    {
        return str_ends_with($value, ':memory:') || str_starts_with($value, '/') ? $value : $root . '/' . $value;
    }

    public static function sqlitePath(string $root, string $dsn): string
    {
        return self::path($root, substr($dsn, 7));
    }
}
