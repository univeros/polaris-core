<?php

declare(strict_types=1);

namespace Polaris\Sso\Saml;

use Polaris\Sso\Identity;
use Polaris\Sso\Model\Provider;
use Polaris\Sso\Sp;
use Polaris\Sso\SsoException;

/**
 * SAML 2.0 against a provider: the AuthnRequest (redirect binding), the Response (POST binding), the
 * SP metadata, single logout in both directions, and a configuration check.
 */
interface SamlProtocol
{
    /**
     * @return array{id: string, url: string} the request id (for InResponseTo) and where to send the browser
     */
    public function authnRequest(Provider $provider, Sp $sp, string $relayState): array;

    /**
     * @param string|null $requestId the AuthnRequest id the response must answer; null for an IdP-initiated response
     * @throws SsoException when the response is not acceptable
     */
    public function consume(Provider $provider, Sp $sp, string $samlResponse, ?string $requestId): Identity;

    public function metadata(Provider $provider, Sp $sp): string;

    /**
     * The IdP's single-logout URL carrying a LogoutRequest for the user; null when the provider has none.
     */
    public function logoutUrl(Provider $provider, Sp $sp, string $nameId, ?string $sessionIndex, string $relayState): ?string;

    /**
     * An IdP's LogoutRequest, signed: by the query signature of the redirect binding (`SigAlg`,
     * `Signature` over `SAMLRequest`, `RelayState`) or by the enveloped XML signature of the POST binding.
     *
     * @param array<string, string> $message `SAMLRequest` and, when present, `RelayState`, `SigAlg`, `Signature`
     * @return array{id: string, name_id: string, session_indexes: list<string>}
     * @throws SsoException when the request is not acceptable
     */
    public function consumeLogoutRequest(Provider $provider, Sp $sp, array $message, bool $deflated): array;

    /**
     * The IdP's single-logout URL carrying the LogoutResponse; null when the provider has none.
     */
    public function logoutResponseUrl(Provider $provider, Sp $sp, string $inResponseTo, ?string $relayState): ?string;

    /**
     * @return list<string> what is wrong; empty when the configuration is complete
     */
    public function check(Provider $provider, Sp $sp): array;
}
