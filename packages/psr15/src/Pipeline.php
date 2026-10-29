<?php

declare(strict_types=1);

namespace Polaris\Psr15;

use Polaris\Psr15\Middleware\AuthenticatedRateLimitMiddleware;
use Polaris\Psr15\Middleware\AuthorizationMiddleware;
use Polaris\Psr15\Middleware\AuthRateLimitMiddleware;
use Polaris\Psr15\Middleware\ClientContextMiddleware;
use Polaris\Psr15\Middleware\DenylistMiddleware;
use Polaris\Psr15\Middleware\MfaTokenMiddleware;
use Polaris\Psr15\Middleware\RateLimiter;
use Polaris\Psr15\Middleware\RefreshCookieMiddleware;
use Polaris\Psr15\Middleware\StepUpMiddleware;
use Polaris\Psr15\Middleware\TokenAuthenticationMiddleware;
use Polaris\Psr15\Middleware\UnauthorizedResponder;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function array_reverse;

/**
 * The PSR-15 face of a Polaris {@see Graph}: the ordered middleware (§5.4) and the request
 * handler, plus a self-contained {@see handle()} for hosts without their own pipeline runner.
 */
final class Pipeline
{
    private readonly Router $router;
    private readonly JsonResponse $json;
    private readonly UnauthorizedResponder $unauthorized;
    private readonly RateLimiter $limiter;

    /**
     * @param bool $bodyDelivery tokens in the body whatever `auth.flows.token_delivery` says: for in-process
     *                           callers with no cookie jar (`polaris/mcp`'s dispatcher, docs/cookie-mode/spec.md §2.11)
     */
    public function __construct(
        private readonly Graph $graph,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly string $pathPrefix = '/',
        private readonly bool $bodyDelivery = false,
    ) {
        $this->router = new Router($graph->manifest(), $pathPrefix);
        $this->json = new JsonResponse($responseFactory);
        $this->unauthorized = new UnauthorizedResponder($responseFactory);
        $this->limiter = new RateLimiter($graph->rateStore(), $graph->clock(), $responseFactory);
    }

    /**
     * Routing first, then the order the 1.0 module registered (by priority): ClientContext,
     * AuthRateLimit, (in cookie token delivery) RefreshCookie, MfaToken, TokenAuthentication (the plugins' bearer resolvers first), the plugins' middleware, StepUp, Denylist,
     * AuthenticatedRateLimit, Authorization. The per-user limiter wraps authorization, so a 403 carries the rate-limit
     * headers, as in 1.0.
     *
     * @return list<MiddlewareInterface>
     */
    public function middleware(): array
    {
        $auth = $this->graph->config()->auth;

        $plugins = [];
        foreach ($this->graph->plugins() as $plugin) {
            foreach ($plugin->middleware($this->graph) as $middleware) {
                $plugins[] = $middleware;
            }
        }

        // Cookie token delivery: after the per-IP limiter (a refused request still spends the budget), before
        // everything that reads the request or the response, so they see body mode (docs/cookie-mode/spec.md §2.3).
        $cookie = $auth->tokenDelivery === 'cookie' && !$this->bodyDelivery
            ? [new RefreshCookieMiddleware($auth, $this->responseFactory, $this->json, $this->pathPrefix)]
            : [];

        return [
            new RouteMiddleware($this->router, $this->json),
            new ClientContextMiddleware(),
            new AuthRateLimitMiddleware($this->graph->rateLimits(), $this->limiter),
            ...$cookie,
            new MfaTokenMiddleware($this->graph->mfaLoginTokens(), $this->unauthorized),
            new TokenAuthenticationMiddleware($this->graph->tokenFactory(), $this->unauthorized, resolvers: $this->graph->bearerResolvers(...)),
            ...$plugins,
            new StepUpMiddleware($this->graph->mfaVerifier(), $auth, $this->graph->clock(), $this->unauthorized, $this->json),
            new DenylistMiddleware($this->graph->denylist(), $auth, $this->json),
            new AuthenticatedRateLimitMiddleware($this->graph->rateLimits(), $this->limiter),
            new AuthorizationMiddleware($this->graph->gate(), $this->unauthorized, $this->json),
        ];
    }

    public function handler(): RequestHandlerInterface
    {
        return new RequestHandler($this->router, $this->graph->endpoint(...), $this->json);
    }

    /**
     * Runs the whole stack for one request.
     */
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $handler = $this->handler();
        foreach (array_reverse($this->middleware()) as $middleware) {
            $handler = new class ($middleware, $handler) implements RequestHandlerInterface {
                public function __construct(private readonly MiddlewareInterface $middleware, private readonly RequestHandlerInterface $next)
                {
                }

                public function handle(ServerRequestInterface $request): ResponseInterface
                {
                    return $this->middleware->process($request, $this->next);
                }
            };
        }

        return $handler->handle($request);
    }
}
