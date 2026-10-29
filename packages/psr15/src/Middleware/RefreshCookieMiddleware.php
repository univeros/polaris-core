<?php

declare(strict_types=1);

namespace Polaris\Psr15\Middleware;

use Override;
use Polaris\Config\AuthConfig;
use Polaris\Http\Attributes;
use Polaris\Http\Endpoint;
use Polaris\Http\Manifest\EndpointSpec;
use Polaris\Psr15\JsonResponse;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use stdClass;

use function in_array;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use function rawurlencode;
use function rtrim;
use function sprintf;
use function strtolower;

use const JSON_THROW_ON_ERROR;

/**
 * Cookie token delivery (docs/cookie-mode/spec.md §2.3): on the routes the manifest marks with
 * `session`, the refresh token travels in an `HttpOnly` cookie instead of the JSON body. Registered by
 * {@see \Polaris\Psr15\Pipeline} only when `auth.flows.token_delivery` is `cookie`, right after the
 * per-IP limiter, so everything behind it (MFA ticket, bearer, the plugins' middleware, the endpoint)
 * sees requests and responses exactly as in body mode.
 *
 * - `issue` and `refresh`: refused over plaintext and without the CSRF guard (§2.5, §2.6); a 200 or 201
 *   carrying `data.refresh_token` loses it to the cookie.
 * - `refresh`: when no input carries `refresh_token`, the cookie's value is put in the parsed body; a
 *   401 clears the cookie when the cookie was the credential.
 * - `end`: a 2xx clears the cookie.
 */
final class RefreshCookieMiddleware implements MiddlewareInterface
{
    public const string COOKIE = '__Secure-polaris_refresh';
    public const string CSRF_HEADER = 'X-Polaris-CSRF';

    private readonly string $path;

    public function __construct(
        private readonly AuthConfig $auth,
        private readonly ResponseFactoryInterface $responses,
        private readonly JsonResponse $json,
        string $pathPrefix = '/',
    ) {
        $this->path = rtrim($pathPrefix, '/') . '/auth/token/refresh';
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $spec = $request->getAttribute(Attributes::ROUTE);
        if (!$spec instanceof EndpointSpec || $spec->session === null) {
            return $handler->handle($request);
        }
        if ($spec->session === 'end') {
            $response = $handler->handle($request);

            return $response->getStatusCode() >= 200 && $response->getStatusCode() < 300 ? $this->clear($response) : $response;
        }

        if ($request->getUri()->getScheme() !== 'https') {
            return $this->refuse($spec, 'insecure_transport', 'Insecure transport', 'Sessions are only issued over HTTPS.');
        }
        if (!$this->sameOrigin($request)) {
            return $this->refuse($spec, 'csrf_failed', 'CSRF check failed', 'The request did not pass the CSRF check.');
        }

        $fromCookie = false;
        if ($spec->session === 'refresh' && !self::carriesRefreshToken($request)) {
            $cookie = $request->getCookieParams()[self::COOKIE] ?? null;
            if (is_string($cookie) && $cookie !== '') {
                $body = $request->getParsedBody();
                $request = $request->withParsedBody([...(is_array($body) ? $body : []), 'refresh_token' => $cookie]);
                $fromCookie = true;
            }
        }

        $response = $handler->handle($request);
        $status = $response->getStatusCode();
        if ($status === 200 || $status === 201) {
            return $this->move($response);
        }
        if ($status === 401 && $fromCookie) {
            return $this->clear($response);
        }

        return $response;
    }

    /**
     * The guard of §2.5: the custom header (a cross-origin page cannot send it without a preflight
     * Polaris never answers), then the `Origin` (or, without one, `Sec-Fetch-Site`) must be this origin
     * or a trusted one.
     */
    private function sameOrigin(ServerRequestInterface $request): bool
    {
        if ($request->getHeaderLine(self::CSRF_HEADER) !== '1') {
            return false;
        }
        if ($request->hasHeader('Origin')) {
            $origin = strtolower($request->getHeaderLine('Origin'));

            return $origin === self::origin($request->getUri()) || in_array($origin, $this->auth->cookieTrustedOrigins, true);
        }
        if ($request->hasHeader('Sec-Fetch-Site')) {
            return $request->getHeaderLine('Sec-Fetch-Site') === 'same-origin';
        }

        return true;
    }

    private static function origin(UriInterface $uri): string
    {
        $port = $uri->getPort();

        return strtolower($uri->getScheme() . '://' . $uri->getHost()) . ($port === null ? '' : ':' . $port);
    }

    /**
     * Whether an input source {@see \Polaris\Http\Input} reads already holds `refresh_token`: the body's
     * wins over the cookie (the body fallback, §8 question 3), and the query's would override it anyway.
     */
    private static function carriesRefreshToken(ServerRequestInterface $request): bool
    {
        $body = $request->getParsedBody();
        $query = $request->getQueryParams();

        return (is_array($body) && isset($body['refresh_token'])) || ($body instanceof stdClass && isset($body->refresh_token)) || isset($query['refresh_token']);
    }

    /**
     * Moves `data.refresh_token` from the body to the cookie. Decoded as objects, so an empty `{}` in the
     * body stays an object, and re-encoded as {@see JsonResponse} encodes; a body without a string
     * `data.refresh_token` (an MFA ticket) passes unchanged.
     */
    private function move(ResponseInterface $response): ResponseInterface
    {
        $decoded = json_decode((string) $response->getBody());
        if (!$decoded instanceof stdClass || !($decoded->data ?? null) instanceof stdClass || !is_string($decoded->data->refresh_token ?? null)) {
            return $response;
        }
        $secret = $decoded->data->refresh_token;
        unset($decoded->data->refresh_token);

        $moved = $this->responses->createResponse($response->getStatusCode(), $response->getReasonPhrase());
        foreach ($response->getHeaders() as $name => $values) {
            if (strtolower($name) !== 'content-length') {
                $moved = $moved->withHeader($name, $values);
            }
        }
        $moved->getBody()->write(json_encode($decoded, JSON_THROW_ON_ERROR));

        return $moved->withAddedHeader('Set-Cookie', $this->cookie(rawurlencode($secret), $this->auth->refreshToken->ttl));
    }

    private function clear(ResponseInterface $response): ResponseInterface
    {
        return $response->withAddedHeader('Set-Cookie', $this->cookie('', 0));
    }

    private function cookie(string $value, int $maxAge): string
    {
        return sprintf('%s=%s; Path=%s; Max-Age=%d; HttpOnly; Secure; SameSite=Strict', self::COOKIE, $value, $this->path, $maxAge);
    }

    /**
     * A refusal in the envelope of the route it refuses (§2.3): core's `{"error", "message"}`, or the
     * problem document plugin routes answer, with the same `error` code.
     */
    private function refuse(EndpointSpec $spec, string $code, string $title, string $message): ResponseInterface
    {
        if ($spec->plugin === null) {
            return $this->json->error(403, $code, $message);
        }

        return $this->json->body(403, [
            'type' => Endpoint::PROBLEM_TYPES . 'cookie/' . $code,
            'title' => $title,
            'status' => 403,
            'detail' => $message,
            'error' => $code,
            'message' => $message,
        ], ['Content-Type' => 'application/problem+json']);
    }
}
