<?php

declare(strict_types=1);

namespace Polaris\Social\Provider;

use Override;
use Polaris\Social\SocialException;
use SensitiveParameter;

use function array_filter;
use function array_values;
use function base64_encode;
use function http_build_query;
use function implode;
use function is_array;
use function is_int;
use function is_string;
use function preg_split;
use function str_contains;

use const PHP_QUERY_RFC3986;

/**
 * Any OAuth 2.0 server from its {@see Definition}: the authorization code grant with PKCE when the
 * definition does it, the client authenticated by a form field or Basic, the profile from the userinfo
 * endpoint, the id_token (OpenID Connect) verified and merged in, a refresh. The catalog's providers
 * and a host's `GenericOAuth` are this class; Apple and GitHub extend it where their protocol differs.
 */
class OAuth2Provider implements Provider
{
    public function __construct(
        protected readonly Definition $definition,
        protected readonly string $clientId,
        #[SensitiveParameter] protected readonly ?string $clientSecret,
        protected readonly Http $http,
        protected readonly IdTokens $idTokens,
    ) {
    }

    #[Override]
    public function id(): string
    {
        return $this->definition->id;
    }

    #[Override]
    public function definition(): Definition
    {
        return $this->definition;
    }

    #[Override]
    public function authorizationUrl(string $redirectUri, string $state, array $scopes, ?string $codeChallenge, string $nonce): string
    {
        $params = [
            $this->definition->clientIdParam => $this->clientId,
            'redirect_uri' => $redirectUri,
            'response_type' => 'code',
            'scope' => implode($this->definition->scopeSeparator, $scopes === [] ? $this->definition->scopes : $scopes),
            'state' => $state,
            ...$this->definition->authorizationParams,
        ];
        if ($codeChallenge !== null) {
            $params['code_challenge'] = $codeChallenge;
            $params['code_challenge_method'] = 'S256';
        }
        if ($this->definition->oidc()) {
            $params['nonce'] = $nonce;
        }
        if ($this->definition->formPost) {
            $params['response_mode'] = 'form_post';
        }

        return $this->definition->authorizationEndpoint . (str_contains($this->definition->authorizationEndpoint, '?') ? '&' : '?') . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    #[Override]
    public function exchange(string $code, string $redirectUri, ?string $codeVerifier, string $nonce, array $callback): Tokens
    {
        $form = ['grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => $redirectUri];
        if ($codeVerifier !== null) {
            $form['code_verifier'] = $codeVerifier;
        }

        return $this->tokens($this->http->postForm($this->definition->tokenEndpoint, $this->authenticated($form), $this->clientHeaders()));
    }

    #[Override]
    public function profile(Tokens $tokens, string $nonce, array $callback): Profile
    {
        $claims = [];
        if ($this->definition->oidc() && $tokens->idToken !== null) {
            $claims = $this->idTokens->verify($this->definition, $this->clientId, $tokens->idToken, $nonce);
        }
        if ($this->definition->profileInTokenResponse) {
            return ($this->definition->profile)([...$claims, ...$tokens->raw]);
        }
        if ($this->definition->userinfoEndpoint === null) {
            if ($claims === []) {
                throw new SocialException(SocialException::PROVIDER_ERROR, 'the provider answered no id_token');
            }

            return ($this->definition->profile)($claims);
        }
        $userinfo = $this->http->json($this->definition->userinfoMethod, $this->definition->userinfoEndpoint, $tokens->accessToken, $this->definition->userinfoHeaders);

        return ($this->definition->profile)([...$claims, ...$userinfo]);
    }

    #[Override]
    public function refresh(string $refreshToken): Tokens
    {
        return $this->tokens($this->http->postForm($this->definition->tokenEndpoint, $this->authenticated(['grant_type' => 'refresh_token', 'refresh_token' => $refreshToken]), $this->clientHeaders()));
    }

    #[Override]
    public function verifyIdToken(string $idToken, ?string $nonce): Profile
    {
        if (!$this->definition->oidc()) {
            throw new SocialException(SocialException::INVALID_INPUT, 'This provider does not issue id_tokens.');
        }

        return ($this->definition->profile)($this->idTokens->verify($this->definition, $this->clientId, $idToken, $nonce));
    }

    /**
     * The client's credentials on a token request: a form field, or Basic (the header below).
     *
     * @param array<string, string> $form
     * @return array<string, string>
     */
    protected function authenticated(array $form): array
    {
        $form[$this->definition->clientIdParam] = $this->clientId;
        if ($this->definition->tokenAuth === Definition::AUTH_POST && $this->clientSecret !== null) {
            $form['client_secret'] = $this->clientSecret;
        }

        return $form;
    }

    /**
     * @return array<string, string>
     */
    protected function clientHeaders(): array
    {
        $headers = $this->definition->userinfoHeaders === [] ? [] : array_filter($this->definition->userinfoHeaders, static fn(string $name): bool => $name === 'User-Agent', ARRAY_FILTER_USE_KEY);
        if ($this->definition->tokenAuth === Definition::AUTH_BASIC) {
            $headers['Authorization'] = 'Basic ' . base64_encode($this->clientId . ':' . ($this->clientSecret ?? ''));
        }

        return $headers;
    }

    /**
     * @param array<string, mixed> $body the token endpoint's answer
     * @throws SocialException
     */
    protected function tokens(array $body): Tokens
    {
        $access = $body['access_token'] ?? null;
        if (!is_string($access) || $access === '') {
            throw new SocialException(SocialException::PROVIDER_ERROR, 'the token endpoint answered no access token');
        }
        $scope = $body['scope'] ?? null;
        // A scope list comes back space-separated (RFC 6749) or comma-separated (GitHub, Facebook).
        $scopes = is_string($scope) ? array_values(array_filter(preg_split('/[\s,]+/', $scope) ?: [])) : (is_array($scope) ? array_values(array_filter($scope, 'is_string')) : []);
        $expires = $body['expires_in'] ?? null;

        return new Tokens(
            $access,
            is_string($body['refresh_token'] ?? null) && $body['refresh_token'] !== '' ? $body['refresh_token'] : null,
            is_int($expires) ? $expires : (is_string($expires) && $expires !== '' ? (int) $expires : null),
            $scopes,
            is_string($body['id_token'] ?? null) ? $body['id_token'] : null,
            $body,
        );
    }
}
