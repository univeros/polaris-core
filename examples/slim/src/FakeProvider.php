<?php

declare(strict_types=1);

namespace PolarisDemo;

use Polaris\Social\Provider\Definition;
use Polaris\Social\Provider\Profile;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\App;

use function file_get_contents;
use function http_build_query;
use function in_array;
use function is_string;
use function json_encode;
use function str_contains;

use const JSON_THROW_ON_ERROR;

/**
 * The demo's own OAuth 2 server, for `polaris/social`'s `GenericOAuth` without an account anywhere:
 * `/fake-oauth/authorize` approves at once and sends the browser back with a code, `/fake-oauth/token`
 * turns any code into a token, `/fake-oauth/me` is the one user's profile. Nothing is checked: it is
 * a demo of the flow, not of a provider.
 */
final class FakeProvider
{
    public const string USER = '{"id":"fake-1","email":"fake@example.com","verified":true,"name":"Fake User"}';

    /**
     * The definition `polaris/social` signs in through, as a host passes one for its own OAuth 2 server.
     */
    public static function definition(string $baseUrl): Definition
    {
        return new Definition('fake', 'Fake provider', $baseUrl . '/fake-oauth/authorize', $baseUrl . '/fake-oauth/token', $baseUrl . '/fake-oauth/me', ['profile'], static fn(array $me): Profile => new Profile((string) $me['id'], (string) $me['email'], (bool) $me['verified'], (string) $me['name']), pkce: false);
    }

    /**
     * @param App<\Psr\Container\ContainerInterface|null> $app
     */
    public static function register(App $app, string $root): void
    {
        // The demo's mailbox, for the passkey page to read its verification token.
        $app->get('/mail.log', static function (ServerRequestInterface $request, ResponseInterface $response) use ($root): ResponseInterface {
            // The mailbox holds verification and reset tokens: the demo serves it to the demo's own browser only.
            if (!in_array($request->getServerParams()['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1'], true)) {
                return $response->withStatus(403);
            }
            $response->getBody()->write((string) @file_get_contents($root . '/var/mail.log'));

            return $response->withHeader('Content-Type', 'text/plain');
        });
        $app->get('/fake-oauth/authorize', static function (ServerRequestInterface $request, ResponseInterface $response): ResponseInterface {
            $query = $request->getQueryParams();
            $redirect = is_string($query['redirect_uri'] ?? null) ? $query['redirect_uri'] : '/';
            $location = $redirect . (str_contains($redirect, '?') ? '&' : '?') . http_build_query(['code' => 'fake-code', 'state' => (string) ($query['state'] ?? '')]);

            return $response->withStatus(302)->withHeader('Location', $location);
        });
        $app->post('/fake-oauth/token', static function (ServerRequestInterface $request, ResponseInterface $response): ResponseInterface {
            $response->getBody()->write(json_encode(['access_token' => 'fake-access-token', 'token_type' => 'Bearer', 'expires_in' => 3600, 'scope' => 'profile'], JSON_THROW_ON_ERROR));

            return $response->withHeader('Content-Type', 'application/json');
        });
        $app->get('/fake-oauth/me', static function (ServerRequestInterface $request, ResponseInterface $response): ResponseInterface {
            $response->getBody()->write(self::USER);

            return $response->withHeader('Content-Type', 'application/json');
        });
    }
}
