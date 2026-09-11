<?php

declare(strict_types=1);

namespace Polaris\Sso\Oidc;

use Polaris\Sso\Identity;
use Polaris\Sso\Model\Provider;
use Polaris\Sso\SsoException;
use SensitiveParameter;

/**
 * OpenID Connect against a provider: the authorization request, the code exchange and the id_token
 * verification, the end-session URL, and a configuration check.
 */
interface OidcProtocol
{
    public function authorizationUrl(Provider $provider, string $redirectUri, string $state, string $nonce, string $codeChallenge): string;

    /**
     * @throws SsoException when the exchange or the id_token fails
     */
    public function exchange(Provider $provider, #[SensitiveParameter] ?string $clientSecret, string $code, string $redirectUri, string $codeVerifier, string $nonce): Identity;

    public function endSessionUrl(Provider $provider, ?string $postLogoutRedirectUri): ?string;

    /**
     * @return list<string> what is wrong; empty when the provider is reachable and complete
     */
    public function check(Provider $provider): array;
}
