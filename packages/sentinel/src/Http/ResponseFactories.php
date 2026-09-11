<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Http;

use LogicException;
use Psr\Http\Message\ResponseFactoryInterface;

use function class_exists;

/**
 * The PSR-17 response factory the middleware answers with: the host's, or one of the common
 * implementations when it is installed.
 */
final class ResponseFactories
{
    private const array KNOWN = [
        'HttpSoft\Message\ResponseFactory',
        'Laminas\Diactoros\ResponseFactory',
        'Nyholm\Psr7\Factory\Psr17Factory',
        'Slim\Psr7\Factory\ResponseFactory',
        'GuzzleHttp\Psr7\HttpFactory',
    ];

    public static function discover(): ResponseFactoryInterface
    {
        foreach (self::KNOWN as $class) {
            if (class_exists($class)) {
                $factory = new $class();
                if ($factory instanceof ResponseFactoryInterface) {
                    return $factory;
                }
            }
        }

        throw new LogicException('No PSR-17 response factory found; pass one to SentinelPlugin (responses:).');
    }
}
