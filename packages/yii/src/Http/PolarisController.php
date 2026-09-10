<?php

declare(strict_types=1);

namespace Polaris\Yii\Http;

use Polaris\Http\Attributes;
use Polaris\Psr15\Pipeline;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

use function is_string;

/**
 * Serves every Polaris route: the request runs through the whole Polaris middleware stack and handler,
 * PSR-15 end to end. When `yiisoft/proxy-middleware` resolved the client IP through the trusted
 * proxies, its `requestClientIp` attribute is what Polaris sees.
 */
final readonly class PolarisController
{
    private const string CLIENT_IP_ATTRIBUTE = 'requestClientIp';

    public function __construct(private Pipeline $pipeline)
    {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $ip = $request->getAttribute(self::CLIENT_IP_ATTRIBUTE);
        if (is_string($ip) && $ip !== '') {
            $request = $request->withAttribute(Attributes::IP_ADDRESS, $ip);
        }

        return $this->pipeline->handle($request);
    }
}
