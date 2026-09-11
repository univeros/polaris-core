<?php

declare(strict_types=1);

namespace Polaris\Sso;

use Polaris\Event\UserLoggedIn;
use Polaris\Identity\SessionService;
use Polaris\Model\User;
use Polaris\Repository\UserRepository;
use Polaris\Sso\Model\Provider;
use Polaris\Sso\Oidc\OidcProtocol;
use Polaris\Sso\Saml\SamlProtocol;
use Polaris\Token\ClientContext;
use Polaris\Token\SessionPrincipal;
use Polaris\Token\SessionPrincipalResolverInterface;
use Polaris\Token\TokenService;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\SimpleCache\CacheInterface;

use function base64_encode;
use function bin2hex;
use function hash;
use function in_array;
use function is_array;
use function is_string;
use function max;
use function random_bytes;
use function rtrim;
use function str_contains;
use function strrchr;
use function strtolower;
use function strtr;
use function substr;
use function trim;

/**
 * The sign-in flow: which provider (by id, or by the verified domain of the email), the redirect to the
 * IdP with the state kept in the cache, the callback that validates what came back, resolves or
 * provisions the user, ensures the membership, opens an organization-scoped session (amr `sso`) and
 * hands the tokens over through a one-time code the application exchanges; single logout in both
 * directions. Every rejection is `sso.assertion_rejected` with its reason; the caller sees a generic
 * problem.
 */
final class SsoService
{
    public const string AMR = 'sso';
    private const int STATE_TTL = 600;
    private const int CODE_TTL = 60;
    private const int REPLAY_DRIFT = 180;

    public function __construct(
        private readonly Providers $providers,
        private readonly Domains $domains,
        private readonly Provisioner $provisioner,
        private readonly SsoAudit $audit,
        private readonly Sp $sp,
        private readonly OidcProtocol $oidc,
        private readonly SamlProtocol $saml,
        private readonly CacheInterface $cache,
        private readonly TokenService $tokens,
        private readonly SessionPrincipalResolverInterface $principals,
        private readonly SessionService $sessions,
        private readonly UserRepository $users,
        private readonly EventDispatcherInterface $events,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * Where to send the browser.
     *
     * @return array{url: string, provider_id: string, type: string}
     * @throws SsoException
     */
    public function start(?string $email, ?string $providerId, ?string $redirectUri): array
    {
        $provider = $providerId !== null ? $this->providers->find($providerId) : $this->providerForEmail($email);
        if (!$provider instanceof Provider) {
            throw new SsoException(SsoException::PROVIDER_NOT_FOUND, 'no provider for the request');
        }
        if (!$provider->enabled) {
            throw new SsoException(SsoException::PROVIDER_DISABLED, 'the provider is disabled');
        }
        $redirectUri = $this->redirectUri($provider, $redirectUri);
        $state = bin2hex(random_bytes(16));
        $entry = ['provider_id' => $provider->id, 'redirect_uri' => $redirectUri];
        if ($provider->type === Provider::OIDC) {
            $entry['nonce'] = bin2hex(random_bytes(16));
            $entry['verifier'] = self::base64url(random_bytes(48));
            $url = $this->oidc->authorizationUrl($provider, $this->sp->acsUrl($provider->id), $state, $entry['nonce'], self::base64url(hash('sha256', $entry['verifier'], true)));
        } else {
            $request = $this->saml->authnRequest($provider, $this->sp, $state);
            $entry['request_id'] = $request['id'];
            $url = $request['url'];
        }
        $this->cache->set(self::key('state', $state), $entry, self::STATE_TTL);

        return ['url' => $url, 'provider_id' => $provider->id, 'type' => $provider->type];
    }

    /**
     * The OIDC callback: the application URL to send the browser to, with the hand-off code.
     *
     * @throws SsoException
     */
    public function completeOidc(string $providerId, ?string $code, ?string $state, ?string $error, ClientContext $client): string
    {
        $provider = $this->enabledProvider($providerId, Provider::OIDC);
        $entry = $this->takeState($provider, $state);
        if ($error !== null) {
            $this->reject($provider, 'the provider answered ' . $error, $client);
        }
        if ($code === null || $code === '') {
            $this->reject($provider, 'no code in the callback', $client);
        }
        try {
            $identity = $this->oidc->exchange($provider, $this->providers->secret($provider), (string) $code, $this->sp->acsUrl($provider->id), (string) ($entry['verifier'] ?? ''), (string) ($entry['nonce'] ?? ''));
        } catch (SsoException $exception) {
            $this->reject($provider, $exception->detail, $client);
        }

        return $this->finish($provider, $identity, (string) $entry['redirect_uri'], $client);
    }

    /**
     * The SAML callback (POST binding): the application URL to send the browser to, with the hand-off code.
     *
     * @throws SsoException
     */
    public function completeSaml(string $providerId, ?string $samlResponse, ?string $relayState, ClientContext $client): string
    {
        $provider = $this->enabledProvider($providerId, Provider::SAML);
        if ($samlResponse === null || $samlResponse === '') {
            $this->reject($provider, 'no SAMLResponse in the callback', $client);
        }
        if ($relayState !== null && $relayState !== '') {
            $entry = $this->takeState($provider, $relayState);
            $requestId = is_string($entry['request_id'] ?? null) ? $entry['request_id'] : null;
            $redirectUri = (string) $entry['redirect_uri'];
        } elseif ($provider->flag('idp_initiated')) {
            $requestId = null;
            $redirectUri = $this->redirectUri($provider, null);
        } else {
            $this->reject($provider, 'unsolicited response and the provider does not allow IdP-initiated sign-in', $client);
        }
        try {
            $identity = $this->saml->consume($provider, $this->sp, (string) $samlResponse, $requestId);
        } catch (SsoException $exception) {
            $this->reject($provider, $exception->detail, $client);
        }
        if ($identity->assertionId !== null) {
            $replay = self::key('assertion', hash('sha256', $identity->assertionId));
            if ($this->cache->get($replay) !== null) {
                $this->reject($provider, 'assertion ' . $identity->assertionId . ' replayed', $client);
            }
            $ttl = $identity->notOnOrAfter === null ? self::STATE_TTL : max(1, $identity->notOnOrAfter->getTimestamp() - $this->clock->now()->getTimestamp()) + self::REPLAY_DRIFT;
            $this->cache->set($replay, 1, $ttl);
        }

        return $this->finish($provider, $identity, $redirectUri, $client);
    }

    /**
     * The tokens a hand-off code stands for, once; the login envelope's `data`.
     *
     * @return array<string, mixed>
     * @throws SsoException
     */
    public function exchange(string $code): array
    {
        $key = self::key('code', hash('sha256', $code));
        $tokens = $this->cache->get($key);
        if (!is_array($tokens)) {
            throw new SsoException(SsoException::CODE_INVALID, 'the code is unknown, used or expired');
        }
        $this->cache->delete($key);

        return $tokens;
    }

    /**
     * An IdP's LogoutRequest: every session of the named user ends; the IdP's URL for the LogoutResponse.
     *
     * @param array<string, string> $message `SAMLRequest` and, when present, `RelayState`, `SigAlg`, `Signature`
     * @return string|null null when the provider has no logout response URL
     * @throws SsoException
     */
    public function idpLogout(string $providerId, array $message, bool $deflated, ClientContext $client): ?string
    {
        $provider = $this->enabledProvider($providerId, Provider::SAML);
        try {
            $request = $this->saml->consumeLogoutRequest($provider, $this->sp, $message, $deflated);
        } catch (SsoException $exception) {
            $this->reject($provider, $exception->detail, $client);
        }
        $user = $this->users->findOneBy(['email' => strtolower(trim($request['name_id']))]);
        $revoked = $user instanceof User ? $this->sessions->revokeAll($user->id, 'sso_logout') : 0;
        $this->audit->record(AuditNames::SLO_COMPLETED, 'system', null, $user?->id, $provider->organizationId, ['provider_id' => $provider->id, 'direction' => 'idp', 'sessions_revoked' => $revoked], $client);

        return $this->saml->logoutResponseUrl($provider, $this->sp, $request['id'], $message['RelayState'] ?? null);
    }

    /**
     * The application's logout of an SSO user: their sessions end here; where to send the browser so
     * the IdP ends its own (null when the provider offers no single logout).
     *
     * @throws SsoException
     */
    public function logout(User $user, string $organizationId, ?string $providerId, ?string $postLogoutUri, ClientContext $client): ?string
    {
        $provider = $providerId !== null ? $this->providers->find($providerId) : ($this->providers->forOrganization($organizationId)[0] ?? null);
        if (!$provider instanceof Provider || $provider->organizationId !== $organizationId) {
            throw new SsoException(SsoException::PROVIDER_NOT_FOUND, 'no provider for the organization');
        }
        $revoked = $this->sessions->revokeAll($user->id, 'sso_logout');
        $postLogoutUri = $postLogoutUri === null ? ($provider->redirectUris()[0] ?? null) : $this->redirectUri($provider, $postLogoutUri);
        $url = $provider->type === Provider::OIDC
            ? $this->oidc->endSessionUrl($provider, $postLogoutUri)
            : $this->saml->logoutUrl($provider, $this->sp, $user->email, null, bin2hex(random_bytes(8)));
        $this->audit->record(AuditNames::SLO_COMPLETED, 'user', $user->id, $user->id, $provider->organizationId, ['provider_id' => $provider->id, 'direction' => 'sp', 'sessions_revoked' => $revoked], $client);

        return $url;
    }

    /**
     * @throws SsoException
     */
    public function enabledProvider(string $providerId, string $type): Provider
    {
        $provider = $this->providers->find($providerId);
        if (!$provider instanceof Provider || $provider->type !== $type) {
            throw new SsoException(SsoException::PROVIDER_NOT_FOUND, 'no such provider');
        }
        if (!$provider->enabled) {
            throw new SsoException(SsoException::PROVIDER_DISABLED, 'the provider is disabled');
        }

        return $provider;
    }

    private function providerForEmail(?string $email): ?Provider
    {
        $at = $email === null ? false : strrchr(strtolower(trim($email)), '@');
        if ($at === false) {
            throw new SsoException(SsoException::INVALID_INPUT, 'an email or a provider_id is required');
        }
        $domain = $this->domains->verified(substr($at, 1));

        return $domain === null ? null : $this->providers->find($domain->providerId);
    }

    /**
     * @throws SsoException
     */
    private function redirectUri(Provider $provider, ?string $requested): string
    {
        $allowed = $provider->redirectUris();
        if ($requested === null || $requested === '') {
            return $allowed[0] ?? throw new SsoException(SsoException::INVALID_INPUT, 'the provider has no redirect_uri; pass one');
        }
        if (!in_array($requested, $allowed, true)) {
            throw new SsoException(SsoException::INVALID_INPUT, 'redirect_uri is not one of the provider\'s');
        }

        return $requested;
    }

    /**
     * @return array<string, mixed>
     * @throws SsoException
     */
    private function takeState(Provider $provider, ?string $state): array
    {
        $key = $state === null || $state === '' ? null : self::key('state', $state);
        $entry = $key === null ? null : $this->cache->get($key);
        if ($key !== null) {
            $this->cache->delete($key);
        }
        if (!is_array($entry) || ($entry['provider_id'] ?? null) !== $provider->id) {
            $this->audit->record(AuditNames::ASSERTION_REJECTED, 'system', null, null, $provider->organizationId, ['provider_id' => $provider->id, 'reason' => 'unknown or expired state']);
            throw new SsoException(SsoException::ASSERTION_INVALID, 'unknown or expired state');
        }

        return $entry;
    }

    /**
     * @throws SsoException
     */
    private function finish(Provider $provider, Identity $identity, string $redirectUri, ClientContext $client): string
    {
        try {
            [$user, $provisioned] = $this->provisioner->resolve($provider, $identity);
            $joined = $this->provisioner->ensureMembership($provider, $user);
        } catch (SsoException $exception) {
            $this->audit->record(AuditNames::ASSERTION_REJECTED, 'system', null, null, $provider->organizationId, ['provider_id' => $provider->id, 'reason' => $exception->detail], $client);
            throw $exception;
        }
        $now = $this->clock->now();
        $resolved = $this->principals->resolve($user->id, $provider->organizationId);
        $principal = new SessionPrincipal($user->id, $provider->organizationId, $resolved->roles, $resolved->scope, true, false, [self::AMR], $now->getTimestamp());
        $user->lastLoginAt = $now;
        $user->updatedAt = $now;
        $tokens = $this->tokens->issue($principal, $client);
        $this->events->dispatch(new UserLoggedIn($user->id, $tokens->sessionId, $client->ip, $client->userAgent, [self::AMR]));
        $this->audit->record(AuditNames::SIGNED_IN, 'user', $user->id, $user->id, $provider->organizationId, ['provider_id' => $provider->id, 'type' => $provider->type, 'provisioned' => $provisioned, 'joined' => $joined], $client);
        $code = self::base64url(random_bytes(32));
        $this->cache->set(self::key('code', hash('sha256', $code)), [
            'access_token' => $tokens->accessToken,
            'token_type' => 'Bearer',
            'expires_in' => $tokens->accessExpiresIn,
            'refresh_token' => $tokens->refreshToken,
            'user' => ['id' => $user->id, 'email' => $user->email, 'email_verified' => true],
        ], self::CODE_TTL);

        return $redirectUri . (str_contains($redirectUri, '?') ? '&' : '?') . 'sso_code=' . $code;
    }

    /**
     * @throws SsoException
     */
    private function reject(Provider $provider, string $reason, ClientContext $client): never
    {
        $this->audit->record(AuditNames::ASSERTION_REJECTED, 'system', null, null, $provider->organizationId, ['provider_id' => $provider->id, 'reason' => $reason], $client);

        throw new SsoException(SsoException::ASSERTION_INVALID, $reason);
    }

    private static function key(string $purpose, string $value): string
    {
        return 'polaris.sso.' . $purpose . '.' . $value;
    }

    private static function base64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
