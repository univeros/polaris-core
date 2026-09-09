<?php

declare(strict_types=1);

namespace Polaris\Exception;

use InvalidArgumentException as BaseInvalidArgumentException;
use Psr\SimpleCache\InvalidArgumentException as PsrCacheInvalidArgumentException;

/**
 * Thrown by {@see \Polaris\Support\InMemoryCache} when a cache key is not a legal
 * PSR-16 value (empty, or carrying one of the reserved characters `{}()/\@:`).
 */
final class CacheInvalidArgumentException extends BaseInvalidArgumentException implements
    PsrCacheInvalidArgumentException
{
}
