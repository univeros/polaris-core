<?php

declare(strict_types=1);

namespace Polaris\Social\Provider;

use Firebase\JWT\JWT;
use Override;
use Polaris\Social\SocialException;
use Psr\Clock\ClockInterface;
use SensitiveParameter;

use function is_array;
use function is_string;
use function json_decode;
use function trim;

/**
 * Sign in with Apple: the client secret is a JWT the plugin signs with the team's key (ES256, an hour),
 * the callback is a `form_post` whose `user` field carries the name on the first sign-in only, and the
 * profile is the id_token's claims.
 */
final class AppleProvider extends OAuth2Provider
{
    private const int SECRET_TTL = 3600;

    public function __construct(
        Definition $definition,
        string $clientId,
        private readonly string $teamId,
        private readonly string $keyId,
        #[SensitiveParameter] private readonly string $privateKey,
        Http $http,
        IdTokens $idTokens,
        private readonly ClockInterface $clock,
    ) {
        parent::__construct($definition, $clientId, null, $http, $idTokens);
    }

    #[Override]
    public function profile(Tokens $tokens, string $nonce, array $callback): Profile
    {
        $profile = parent::profile($tokens, $nonce, $callback);
        $user = $callback['user'] ?? null;
        $user = is_string($user) ? json_decode($user, true) : $user;
        $name = is_array($user) && is_array($user['name'] ?? null) ? trim(((string) ($user['name']['firstName'] ?? '')) . ' ' . ((string) ($user['name']['lastName'] ?? ''))) : '';

        return $name === '' ? $profile : new Profile($profile->subject, $profile->email, $profile->emailVerified, $name, $profile->extra);
    }

    #[Override]
    protected function authenticated(array $form): array
    {
        $now = $this->clock->now()->getTimestamp();
        $form['client_id'] = $this->clientId;
        $form['client_secret'] = JWT::encode(['iss' => $this->teamId, 'iat' => $now, 'exp' => $now + self::SECRET_TTL, 'aud' => 'https://appleid.apple.com', 'sub' => $this->clientId], $this->privateKey, 'ES256', $this->keyId);

        return $form;
    }

    #[Override]
    public function verifyIdToken(string $idToken, ?string $nonce): Profile
    {
        if ($idToken === '') {
            throw new SocialException(SocialException::INVALID_INPUT, 'id_token is required.');
        }

        return parent::verifyIdToken($idToken, $nonce);
    }
}
