<?php

declare(strict_types=1);

namespace Polaris\ApiKeys\Http;

use LogicException;
use Psr\Http\Message\ResponseFactoryInterface;

use function class_exists;

/**
 * The PSR-17 response factory the middleware answers with: the host's (`Config::$responseFactory` or
 * the plugin's `responses:`), or one of the common implementations when it is installed.
 */
final class Responses
{
    /** @var list<class-string<ResponseFactoryInterface>> none is required; a host with another passes it */
    private const array KNOWN = [
        'HttpSoft\Message\ResponseFactory',
        'Laminas\Diactoros\ResponseFactory',
        'Nyholm\Psr7\Factory\Psr17Factory',
        'GuzzleHttp\Psr7\HttpFactory',
    ];

    public static function discover(): ResponseFactoryInterface
    {
        foreach (self::KNOWN as $class) {
            if (class_exists($class)) {
                return new $class();
            }
        }
        throw new LogicException('No PSR-17 response factory found; pass one to ApiKeysPlugin (responses:).');
    }
}
