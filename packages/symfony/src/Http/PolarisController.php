<?php

declare(strict_types=1);

namespace Polaris\Symfony\Http;

use Polaris\Http\Attributes;
use Polaris\Psr15\Pipeline;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

use function is_string;

/**
 * Serves every Polaris route: the Symfony request becomes a PSR-7 request (with the client IP Symfony
 * resolved through its trusted proxies), runs through the whole Polaris middleware stack and handler,
 * and the PSR-7 response comes back as a Symfony one. Nothing is added or changed on the way.
 */
final readonly class PolarisController
{
    public function __construct(
        private Pipeline $pipeline,
        private PsrHttpFactory $psr,
        private HttpFoundationFactory $foundation,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        $psrRequest = $this->psr->createRequest($request);
        $ip = $request->getClientIp();
        if (is_string($ip) && $ip !== '') {
            $psrRequest = $psrRequest->withAttribute(Attributes::IP_ADDRESS, $ip);
        }

        return $this->foundation->createResponse($this->pipeline->handle($psrRequest));
    }
}
