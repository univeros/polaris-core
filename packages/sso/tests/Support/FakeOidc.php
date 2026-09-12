<?php

declare(strict_types=1);

namespace Polaris\Sso\Tests\Support;

use Override;
use Polaris\Sso\Identity;
use Polaris\Sso\Model\Provider;
use Polaris\Sso\Oidc\OidcProtocol;
use Polaris\Sso\SsoException;

/**
 * A deterministic OIDC: the authorization URL names the provider only (the state and nonce are kept
 * here for the test to read), the code `good` is the identity of `$email`, anything else is refused.
 */
final class FakeOidc implements OidcProtocol
{
    public static ?string $lastState = null;
    public static ?string $lastNonce = null;
    /** @var list<string> */
    public static array $problems = [];

    public function __construct(public string $email = 'ada@acme.example', public ?string $name = 'Ada Lovelace')
    {
    }

    #[Override]
    public function authorizationUrl(Provider $provider, string $redirectUri, string $state, string $nonce, string $codeChallenge): string
    {
        self::$lastState = $state;
        self::$lastNonce = $nonce;

        return 'https://idp.example/authorize?client_id=' . $provider->setting('client_id');
    }

    #[Override]
    public function exchange(Provider $provider, ?string $clientSecret, string $code, string $redirectUri, string $codeVerifier, string $nonce): Identity
    {
        if ($code !== 'good' || $nonce !== self::$lastNonce) {
            throw new SsoException(SsoException::ASSERTION_INVALID, 'the code is not good');
        }

        return new Identity('subject-' . $this->email, $this->email, $this->name, ['email' => $this->email]);
    }

    #[Override]
    public function endSessionUrl(Provider $provider, ?string $postLogoutRedirectUri): ?string
    {
        return $provider->flag('no_logout') ? null : 'https://idp.example/logout?post_logout_redirect_uri=' . (string) $postLogoutRedirectUri;
    }

    #[Override]
    public function check(Provider $provider): array
    {
        return self::$problems;
    }
}
