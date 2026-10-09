<?php

declare(strict_types=1);

namespace Polaris\Social\Provider;

use Polaris\Social\SocialException;
use SensitiveParameter;

/**
 * An OAuth 2.0 / OpenID Connect provider: where to send the browser, the code for tokens, the tokens for
 * a profile, a refresh, and (OpenID Connect) an id_token on its own for One Tap. {@see OAuth2Provider}
 * does this from a {@see Definition}; a provider whose protocol differs has its own class.
 */
interface Provider
{
    public function id(): string;

    public function definition(): Definition;

    /**
     * @param list<string> $scopes
     */
    public function authorizationUrl(string $redirectUri, string $state, array $scopes, ?string $codeChallenge, string $nonce): string;

    /**
     * @param array<string, mixed> $callback every parameter the callback carried (Apple's `user`)
     * @throws SocialException the exchange failed
     */
    public function exchange(#[SensitiveParameter] string $code, string $redirectUri, ?string $codeVerifier, string $nonce, array $callback): Tokens;

    /**
     * @param array<string, mixed> $callback
     * @throws SocialException no profile could be read
     */
    public function profile(Tokens $tokens, string $nonce, array $callback): Profile;

    /**
     * @throws SocialException the provider refused, or has no refresh
     */
    public function refresh(#[SensitiveParameter] string $refreshToken): Tokens;

    /**
     * Verifies an id_token the client obtained itself (Google One Tap) and reads the profile from it.
     *
     * @throws SocialException not an OpenID Connect provider, or the token does not verify
     */
    public function verifyIdToken(#[SensitiveParameter] string $idToken, ?string $nonce): Profile;
}
