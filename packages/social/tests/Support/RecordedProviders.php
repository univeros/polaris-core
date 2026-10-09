<?php

declare(strict_types=1);

namespace Polaris\Social\Tests\Support;

use Firebase\JWT\JWT;
use Laminas\Diactoros\Response;
use Polaris\Social\Provider\Definition;
use Polaris\Social\Provider\Profile;
use Polaris\Sso\Tests\Support\RoutingHttpClient;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

use function array_filter;
use function array_map;
use function array_values;
use function file_get_contents;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use function parse_str;
use function parse_url;
use function time;

use const JSON_THROW_ON_ERROR;
use const PHP_URL_QUERY;

/**
 * The providers' recorded answers (`providers/*.json`, one body per URL: discovery documents, token
 * responses, profiles) behind a routing PSR-18 client, with the id_tokens minted at test time under the
 * committed test key (`keys/idp-rsa.pem`, whose public half is the recorded `jwks.json`) for the nonce
 * the test read from the authorization URL. Nothing leaves the process.
 */
final class RecordedProviders
{
    public const string KID = 'test-2026';
    public const string GOOGLE_SUB = '110169484474386276334';
    public const string APPLE_SUB = '001234.abcdef1234567890abcdef1234567890.1234';
    public const string MICROSOFT_SUB = 'AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHza9xbEXZk';
    public const string MICROSOFT_ISSUER = 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0';

    public static ?string $nonce = null;
    /** @var array<string, array<string, mixed>> claims to put in the next minted id_token, by provider id */
    public static array $claims = [];

    public readonly RoutingHttpClient $http;

    public function __construct()
    {
        $this->http = new RoutingHttpClient();
        foreach (['google', 'github', 'apple', 'microsoft'] as $provider) {
            $recorded = json_decode((string) file_get_contents(__DIR__ . '/providers/' . $provider . '.json'), true);
            foreach (is_array($recorded) ? $recorded : [] as $url => $body) {
                $this->http->on((string) $url, $this->answer($provider, $body));
            }
        }
        // Any other OAuth 2 server (`GenericOAuth`) and an OpenID Connect issuer discovered at first use.
        $this->http->on('https://acme.example/oauth/token', ['access_token' => 'acme-access', 'token_type' => 'Bearer', 'expires_in' => 7200, 'refresh_token' => 'acme-refresh', 'scope' => 'profile']);
        $this->http->on('https://acme.example/oauth/me', ['id' => 'acme-42', 'email' => 'eve@example.com', 'verified' => true, 'name' => 'Eve']);
        $this->http->on('https://acme.okta.example/.well-known/openid-configuration', ['issuer' => 'https://acme.okta.example', 'authorization_endpoint' => 'https://acme.okta.example/oauth2/v1/authorize', 'token_endpoint' => 'https://acme.okta.example/oauth2/v1/token', 'userinfo_endpoint' => 'https://acme.okta.example/oauth2/v1/userinfo', 'jwks_uri' => 'https://acme.okta.example/oauth2/v1/keys']);
        $this->http->on('https://acme.okta.example/oauth2/v1/keys', self::jwks());
        $this->http->on('https://acme.okta.example/oauth2/v1/token', static fn(): ResponseInterface => self::respond(['access_token' => 'okta-access', 'token_type' => 'Bearer', 'expires_in' => 3600, 'id_token' => self::mint('https://acme.okta.example', 'okta-client', 'okta-7', 'frank@example.com', true, 'Frank')]));
        $this->http->on('https://acme.okta.example/oauth2/v1/userinfo', ['sub' => 'okta-7', 'email' => 'frank@example.com', 'email_verified' => true, 'name' => 'Frank']);
    }

    /**
     * A later answer for a URL (another profile for the same provider).
     */
    public function on(string $url, mixed $body): void
    {
        $this->http->on($url, $body);
    }

    /**
     * @param array<string, mixed> $body
     */
    public static function respond(array $body): ResponseInterface
    {
        $response = new Response(status: 200, headers: ['Content-Type' => 'application/json']);
        $response->getBody()->write(json_encode($body, JSON_THROW_ON_ERROR));
        $response->getBody()->rewind();

        return $response;
    }

    /**
     * The definition a host passes for its own OAuth 2 server.
     */
    public static function acme(): Definition
    {
        return new Definition('acme', 'Acme', 'https://acme.example/oauth/authorize', 'https://acme.example/oauth/token', 'https://acme.example/oauth/me', ['profile'], static fn(array $data): Profile => new Profile((string) $data['id'], is_string($data['email'] ?? null) ? $data['email'] : null, (bool) ($data['verified'] ?? false), is_string($data['name'] ?? null) ? $data['name'] : null), pkce: false);
    }

    /**
     * @return array<string, mixed>
     */
    public static function jwks(): array
    {
        $jwks = json_decode((string) file_get_contents(__DIR__ . '/providers/jwks.json'), true);

        return is_array($jwks) ? $jwks : [];
    }

    public static function appleClientKey(): string
    {
        return (string) file_get_contents(__DIR__ . '/keys/apple-client.pem');
    }

    /**
     * An id_token signed by the test key: the standard claims, the nonce the test last read, and what
     * the test asked for on top (`$claims[$provider]`).
     */
    public static function mint(string $issuer, string $audience, string $subject, ?string $email, bool $verified, ?string $name, ?string $provider = null): string
    {
        $claims = ['iss' => $issuer, 'aud' => $audience, 'sub' => $subject, 'iat' => time(), 'exp' => time() + 3600, 'nonce' => self::$nonce];
        if ($email !== null) {
            $claims['email'] = $email;
            $claims['email_verified'] = $verified;
        }
        if ($name !== null) {
            $claims['name'] = $name;
        }
        $claims = [...$claims, ...($provider === null ? [] : (self::$claims[$provider] ?? []))];

        return JWT::encode(array_filter($claims, static fn(mixed $value): bool => $value !== null), (string) file_get_contents(__DIR__ . '/keys/idp-rsa.pem'), 'RS256', self::KID);
    }

    /**
     * The nonce (or another parameter) of an authorization URL.
     */
    public static function param(string $url, string $name): string
    {
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        return (string) ($query[$name] ?? '');
    }

    /**
     * The form fields of a recorded token request.
     *
     * @return array<string, string>
     */
    public static function form(RequestInterface $request): array
    {
        parse_str((string) $request->getBody(), $form);

        /** @var array<string, string> $form */
        return array_filter($form, 'is_string');
    }

    private function answer(string $provider, mixed $body): mixed
    {
        if ($body === '<jwks>') {
            return self::jwks();
        }
        if (is_array($body) && ($body['id_token'] ?? null) === '<minted>') {
            return function () use ($provider, $body): ResponseInterface {
                $body['id_token'] = match ($provider) {
                    'google' => self::mint('https://accounts.google.com', 'google-client', self::GOOGLE_SUB, 'ada@example.com', true, 'Ada Lovelace', 'google'),
                    'apple' => self::mint('https://appleid.apple.com', 'com.example.app', self::APPLE_SUB, 'alan@example.com', true, null, 'apple'),
                    default => self::mint(self::MICROSOFT_ISSUER, 'ms-client', self::MICROSOFT_SUB, 'linus@example.com', true, 'Linus Torvalds', 'microsoft'),
                };

                return self::respond($body);
            };
        }

        return $body;
    }

    /**
     * @return list<string> the recorded request bodies, oldest first
     */
    public function bodies(): array
    {
        return array_values(array_filter(array_map(static fn(RequestInterface $request): string => (string) $request->getBody(), $this->http->requests), static fn(string $body): bool => $body !== ''));
    }
}
