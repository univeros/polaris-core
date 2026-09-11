<?php

declare(strict_types=1);

namespace Polaris\Sso\Tests\Support;

use DateTimeImmutable;
use Override;
use Polaris\Sso\Identity;
use Polaris\Sso\Model\Provider;
use Polaris\Sso\Saml\SamlProtocol;
use Polaris\Sso\Sp;
use Polaris\Sso\SsoException;

/**
 * A deterministic SAML: the AuthnRequest id is kept here for the test to read; a response `good:<email>`
 * is that email's identity (assertion id `assertion-<email>`), `unsolicited:<email>` the same without
 * answering a request, anything else is refused; a logout request `logout:<email>` names the email.
 */
final class FakeSaml implements SamlProtocol
{
    public static ?string $lastRequestId = null;
    public static ?string $lastRelayState = null;

    #[Override]
    public function authnRequest(Provider $provider, Sp $sp, string $relayState): array
    {
        self::$lastRequestId = 'request-' . $provider->id;
        self::$lastRelayState = $relayState;

        return ['id' => self::$lastRequestId, 'url' => (string) $provider->setting('sso_url') . '?SAMLRequest=fake'];
    }

    #[Override]
    public function consume(Provider $provider, Sp $sp, string $samlResponse, ?string $requestId): Identity
    {
        [$kind, $email] = [...explode(':', $samlResponse, 2), ''];
        if ($kind === 'good' && $requestId !== self::$lastRequestId) {
            throw new SsoException(SsoException::ASSERTION_INVALID, 'InResponseTo does not match');
        }
        if (!in_array($kind, ['good', 'unsolicited'], true) || $email === '') {
            throw new SsoException(SsoException::ASSERTION_INVALID, 'the response is not good');
        }

        return new Identity($email, $email, null, ['email' => [$email]], 'assertion-' . $email, new DateTimeImmutable('+5 minutes'), 'session-1');
    }

    #[Override]
    public function metadata(Provider $provider, Sp $sp): string
    {
        return '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="fake"/>';
    }

    #[Override]
    public function logoutUrl(Provider $provider, Sp $sp, string $nameId, ?string $sessionIndex, string $relayState): ?string
    {
        $slo = $provider->setting('slo_url');

        return $slo === null ? null : $slo . '?SAMLRequest=fake-logout';
    }

    #[Override]
    public function consumeLogoutRequest(Provider $provider, Sp $sp, array $message, bool $deflated): array
    {
        [$kind, $email] = [...explode(':', $message['SAMLRequest'] ?? '', 2), ''];
        if ($kind !== 'logout' || $email === '') {
            throw new SsoException(SsoException::ASSERTION_INVALID, 'the logout request is not good');
        }

        return ['id' => 'logout-request-1', 'name_id' => $email, 'session_indexes' => ['session-1']];
    }

    #[Override]
    public function logoutResponseUrl(Provider $provider, Sp $sp, string $inResponseTo, ?string $relayState): ?string
    {
        $slo = $provider->setting('slo_url');

        return $slo === null ? null : $slo . '?SAMLResponse=fake-response&InResponseTo=' . $inResponseTo;
    }

    #[Override]
    public function check(Provider $provider, Sp $sp): array
    {
        return $provider->setting('certificate') === 'broken' ? ['certificate does not parse as X.509'] : [];
    }
}
