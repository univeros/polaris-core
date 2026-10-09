<?php

declare(strict_types=1);

namespace PolarisDemo;

use DateInterval;
use DateTimeImmutable;
use Override;
use Psr\SimpleCache\CacheInterface;

use function file_get_contents;
use function file_put_contents;
use function glob;
use function hash;
use function is_array;
use function is_dir;
use function is_file;
use function mkdir;
use function serialize;
use function time;
use function unlink;
use function unserialize;

/**
 * A PSR-16 cache in files, for the demo only: `php -S` runs every request in a fresh process, and the
 * sso, social and passkey plugins keep their short-lived state (an OAuth state, a passkey challenge,
 * a hand-off code) in the graph's cache. A real host shares a Redis or an APCu cache instead.
 */
final class FileCache implements CacheInterface
{
    public function __construct(private readonly string $directory)
    {
        if (!is_dir($directory)) {
            mkdir($directory, 0700, true);
        }
    }

    #[Override]
    public function get(string $key, mixed $default = null): mixed
    {
        $file = $this->file($key);
        if (!is_file($file)) {
            return $default;
        }
        $entry = unserialize((string) file_get_contents($file), ['allowed_classes' => [DateTimeImmutable::class]]);
        if (!is_array($entry) || ($entry['expires'] !== null && $entry['expires'] <= time())) {
            @unlink($file);

            return $default;
        }

        return $entry['value'];
    }

    #[Override]
    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        $seconds = $ttl instanceof DateInterval ? (new DateTimeImmutable())->add($ttl)->getTimestamp() - time() : $ttl;

        return file_put_contents($this->file($key), serialize(['expires' => $seconds === null ? null : time() + $seconds, 'value' => $value])) !== false;
    }

    #[Override]
    public function delete(string $key): bool
    {
        $file = $this->file($key);

        return !is_file($file) || @unlink($file);
    }

    #[Override]
    public function clear(): bool
    {
        foreach ((array) glob($this->directory . '/*.cache') as $file) {
            @unlink((string) $file);
        }

        return true;
    }

    #[Override]
    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $values = [];
        foreach ($keys as $key) {
            $values[$key] = $this->get($key, $default);
        }

        return $values;
    }

    #[Override]
    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set((string) $key, $value, $ttl);
        }

        return true;
    }

    #[Override]
    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }

    #[Override]
    public function has(string $key): bool
    {
        return $this->get($key) !== null;
    }

    private function file(string $key): string
    {
        return $this->directory . '/' . hash('sha256', $key) . '.cache';
    }
}
