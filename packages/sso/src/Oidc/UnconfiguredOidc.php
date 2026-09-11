<?php

declare(strict_types=1);

namespace Polaris\Sso\Oidc;

use Override;
use Polaris\Sso\Identity;
use Polaris\Sso\Model\Provider;
use Polaris\Sso\SsoException;
use SensitiveParameter;

/**
 * What OIDC is when the plugin has no HTTP client: every OIDC provider is refused with the reason.
 */
final class UnconfiguredOidc implements OidcProtocol
{
    private const string REASON = 'OIDC needs an HTTP client: pass httpClient, requestFactory and streamFactory to SsoPlugin';

    #[Override]
    public function authorizationUrl(Provider $provider, string $redirectUri, string $state, string $nonce, string $codeChallenge): string
    {
        throw new SsoException(SsoException::PROVIDER_DISABLED, self::REASON);
    }

    #[Override]
    public function exchange(Provider $provider, #[SensitiveParameter] ?string $clientSecret, string $code, string $redirectUri, string $codeVerifier, string $nonce): Identity
    {
        throw new SsoException(SsoException::PROVIDER_DISABLED, self::REASON);
    }

    #[Override]
    public function endSessionUrl(Provider $provider, ?string $postLogoutRedirectUri): ?string
    {
        return null;
    }

    #[Override]
    public function check(Provider $provider): array
    {
        return [self::REASON];
    }
}
