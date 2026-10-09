<?php

declare(strict_types=1);

namespace Polaris\Social;

use DateInterval;
use Polaris\Identity\EmailNormalizer;
use Polaris\Model\User;
use Polaris\Security\Pepper;
use Polaris\Social\Event\SocialEvent;
use Polaris\Social\Model\Account;
use Polaris\Social\Provider\Profile;
use Polaris\Social\Provider\Provider;
use Polaris\Social\Provider\Tokens;
use Polaris\Token\ClientContext;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\SimpleCache\CacheInterface;
use SensitiveParameter;

use function array_map;
use function base64_decode;
use function base64_encode;
use function bin2hex;
use function count;
use function explode;
use function hash;
use function hash_equals;
use function http_build_query;
use function in_array;
use function is_array;
use function is_int;
use function is_string;
use function json_decode;
use function json_encode;
use function preg_match;
use function random_bytes;
use function rawurlencode;
use function rtrim;
use function str_contains;
use function strtr;

use const DATE_ATOM;
use const JSON_THROW_ON_ERROR;
use const PHP_QUERY_RFC3986;

/**
 * The sign-in and linking flows over the providers: the authorization request with its state (in the
 * cache, ten minutes), the callback (the code for tokens, the tokens for a profile, the linking policy,
 * a session or a link), the one-minute hand-off code the browser exchanges, One Tap, the accounts, and
 * a provider token on the user's behalf. Through the OAuth proxy, a preview deployment's state carries
 * its own callback signed under the pepper the deployments share, and the stable origin forwards to it.
 */
final class SocialService
{
    private const int CODE_TTL = 60;
    private const string PROXY_CONTEXT = 'social:proxy';
    private const string PROXY_SEPARATOR = '.';

    public function __construct(
        private readonly Settings $settings,
        private readonly Providers $providers,
        private readonly Accounts $accounts,
        private readonly Sessions $sessions,
        private readonly CacheInterface $cache,
        private readonly Pepper $pepper,
        private readonly EventDispatcherInterface $events,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * @param list<string> $scopes
     * @return array{url: string, state: string}
     * @throws SocialException
     */
    public function start(string $providerId, ?string $redirectUri, array $scopes, ?string $linkUserId): array
    {
        $provider = $this->providers->get($providerId);
        $redirectUri = $this->redirectUri($redirectUri);
        $callback = $this->settings->callbackUrl($providerId);
        $state = bin2hex(random_bytes(16));
        if ($this->settings->proxied()) {
            // The provider sends the browser to the stable origin, which forwards to this callback; the
            // payload names the provider and expires with the state.
            $payload = self::base64url(json_encode(['return_to' => $callback, 'provider' => $providerId, 'exp' => $this->clock->now()->getTimestamp() + $this->settings->stateTtl], JSON_THROW_ON_ERROR));
            $state .= self::PROXY_SEPARATOR . $payload . self::PROXY_SEPARATOR . self::base64url($this->pepper->hash(self::PROXY_CONTEXT, $state . self::PROXY_SEPARATOR . $payload));
            $callback = $this->settings->proxy . '/social/' . $providerId . '/callback';
        }
        $entry = ['provider' => $providerId, 'redirect_uri' => $redirectUri, 'callback' => $callback, 'nonce' => bin2hex(random_bytes(16)), 'link_user_id' => $linkUserId, 'verifier' => null];
        $challenge = null;
        if ($provider->definition()->pkce) {
            $entry['verifier'] = self::base64url(random_bytes(48));
            $challenge = self::base64url(hash('sha256', $entry['verifier'], true));
        }
        $this->cache->set(self::key('state', $state), $entry, $this->settings->stateTtl);

        return ['url' => $provider->authorizationUrl($callback, $state, $scopes, $challenge, $entry['nonce']), 'state' => $state];
    }

    /**
     * The callback: the application URL to send the browser to, with the hand-off code; or, on the
     * stable origin of the proxy, the preview's callback with everything the provider sent.
     *
     * @param array<string, mixed> $params
     * @throws SocialException
     */
    public function callback(string $providerId, array $params, ClientContext $client): string
    {
        $state = is_string($params['state'] ?? null) ? $params['state'] : '';
        $forward = $this->forwardTo($state, $providerId);
        if ($forward !== null) {
            return $forward . (str_contains($forward, '?') ? '&' : '?') . http_build_query(array_map(static fn(mixed $value): string => is_string($value) ? $value : json_encode($value, JSON_THROW_ON_ERROR), $params), '', '&', PHP_QUERY_RFC3986);
        }
        $entry = $this->takeState($providerId, $state);
        $provider = $this->providers->get($providerId);
        if (is_string($params['error'] ?? null) && $params['error'] !== '') {
            $this->reject($providerId, 'the provider answered ' . $params['error'], $client);
        }
        $code = $params['code'] ?? null;
        if (!is_string($code) || $code === '') {
            $this->reject($providerId, 'no code in the callback', $client);
        }
        try {
            $tokens = $provider->exchange($code, (string) $entry['callback'], is_string($entry['verifier']) ? $entry['verifier'] : null, (string) $entry['nonce'], $params);
            $profile = $provider->profile($tokens, (string) $entry['nonce'], $params);
        } catch (SocialException $exception) {
            $this->reject($providerId, $exception->detail, $client);
        }
        $outcome = $this->finish($provider, $profile, $tokens, is_string($entry['link_user_id']) ? $entry['link_user_id'] : null, $client);
        $code = self::base64url(random_bytes(32));
        $this->cache->set(self::key('code', hash('sha256', $code)), $outcome, self::CODE_TTL);
        $redirectUri = (string) $entry['redirect_uri'];

        // The state goes back too, so the application can check it started this flow (login CSRF).
        return $redirectUri . (str_contains($redirectUri, '?') ? '&' : '?') . 'code=' . $code . '&state=' . rawurlencode($state);
    }

    /**
     * The outcome a hand-off code stands for, once: the login envelope, or the linked account.
     *
     * @return array<string, mixed>
     * @throws SocialException
     */
    public function exchange(#[SensitiveParameter] string $code): array
    {
        $key = self::key('code', hash('sha256', $code));
        $outcome = $this->cache->get($key);
        $this->cache->delete($key);
        if (!is_array($outcome)) {
            throw new SocialException(SocialException::CODE_INVALID, 'The code is unknown, used or expired.');
        }

        /** @var array<string, mixed> $outcome */
        return $outcome;
    }

    /**
     * An id_token the client obtained itself (Google One Tap): verified offline against the provider's
     * keys, then the same policy as a callback.
     *
     * @return array<string, mixed>
     * @throws SocialException
     */
    public function idTokenSignIn(string $providerId, #[SensitiveParameter] string $idToken, ClientContext $client): array
    {
        $provider = $this->providers->get($providerId);
        try {
            $profile = $provider->verifyIdToken($idToken, null);
        } catch (SocialException $exception) {
            if ($exception->reason === SocialException::INVALID_INPUT) {
                throw $exception;
            }
            $this->reject($providerId, $exception->detail, $client);
        }

        return $this->finish($provider, $profile, new Tokens('', null, null, [], $idToken), null, $client);
    }

    /**
     * @return list<Account>
     */
    public function accounts(string $userId): array
    {
        return $this->accounts->forUser($userId);
    }

    /**
     * @throws SocialException not linked, or the user's last way in
     */
    public function unlink(string $userId, string $providerId): void
    {
        $account = $this->accounts->forUserAndProvider($userId, $providerId);
        if ($account === null) {
            throw new SocialException(SocialException::NOT_LINKED, 'No ' . $providerId . ' account is linked.');
        }
        $user = $this->sessions->find($userId);
        if ($user instanceof User && $user->passwordHash === null && count($this->accounts->forUser($userId)) === 1) {
            throw new SocialException(SocialException::LAST_CREDENTIAL, 'This is the only way to sign in to the account; set a password or link another provider first.');
        }
        $this->accounts->unlink($account);
        $this->events->dispatch(new SocialEvent(AuditNames::UNLINKED, $userId, $providerId, ['account_id' => $account->providerAccountId]));
    }

    /**
     * A provider access token for the user, refreshed when it expires within a minute.
     *
     * @return array{access_token: string, expires_at: ?string, scopes: list<string>}
     * @throws SocialException
     */
    public function token(string $userId, string $providerId): array
    {
        $account = $this->accounts->forUserAndProvider($userId, $providerId);
        if ($account === null) {
            throw new SocialException(SocialException::NOT_LINKED, 'No ' . $providerId . ' account is linked.');
        }
        $accessToken = $this->accounts->accessToken($account);
        $expiring = $account->expiresAt !== null && $account->expiresAt <= $this->clock->now()->add(new DateInterval('PT60S'));
        if ($accessToken === null || $accessToken === '' || $expiring) {
            $refreshToken = $this->accounts->refreshToken($account);
            if ($refreshToken === null) {
                throw new SocialException(SocialException::NO_REFRESH, 'The provider token expired and cannot be refreshed; sign in with the provider again.');
            }
            $tokens = $this->providers->get($providerId)->refresh($refreshToken);
            $this->accounts->storeTokens($account, $tokens);
            $accessToken = $tokens->accessToken;
            $this->events->dispatch(new SocialEvent(AuditNames::TOKEN_REFRESHED, $userId, $providerId));
        }

        return ['access_token' => $accessToken, 'expires_at' => $account->expiresAt?->format(DATE_ATOM), 'scopes' => $account->scopes];
    }

    /**
     * The linking policy, then a session or a link.
     *
     * @return array<string, mixed>
     * @throws SocialException
     */
    private function finish(Provider $provider, Profile $profile, Tokens $tokens, ?string $linkUserId, ClientContext $client): array
    {
        $providerId = $provider->id();
        if ($profile->subject === '') {
            $this->reject($providerId, 'the profile carries no subject', $client);
        }
        $account = $this->accounts->find($providerId, $profile->subject);
        if ($linkUserId !== null) {
            return $this->link($providerId, $profile, $tokens, $linkUserId, $account, $client);
        }
        if ($account !== null) {
            $user = $this->sessions->find($account->userId);
            if (!$user instanceof User) {
                $this->reject($providerId, 'the linked user is gone', $client);
            }
            $this->accounts->update($account, $profile, $tokens);
            $this->events->dispatch(new SocialEvent(AuditNames::SIGNED_IN, $user->id, $providerId, ['account_id' => $profile->subject, 'linked' => false], $client->ip, $client->userAgent));

            return $this->sessions->open($user, $providerId, $client);
        }
        $email = $profile->email === null ? null : EmailNormalizer::normalize($profile->email);
        $user = $email === null ? null : $this->sessions->byEmail($email);
        if ($user instanceof User) {
            if (!$this->settings->trusts($providerId) || !$profile->emailVerified) {
                $this->events->dispatch(new SocialEvent(AuditNames::REJECTED, $user->id, $providerId, ['reason' => 'account exists; the provider is not trusted to link it'], $client->ip, $client->userAgent));

                throw new SocialException(SocialException::ACCOUNT_EXISTS, 'An account with this email exists; sign in and link the provider from your account.');
            }
            if ($user->emailVerifiedAt === null) {
                // Nobody had proved this mailbox: whoever registered it (a password, an unverified provider)
                // did not own it. The provider just did, so the account is the provider's user's now.
                $this->sessions->claim($user);
                $this->accounts->unlinkAll($user->id);
            }
            $this->accounts->link($user->id, $providerId, $profile, $tokens);
            $this->events->dispatch(new SocialEvent(AuditNames::LINKED, $user->id, $providerId, ['account_id' => $profile->subject, 'trusted' => true], $client->ip, $client->userAgent));
            $this->events->dispatch(new SocialEvent(AuditNames::SIGNED_IN, $user->id, $providerId, ['account_id' => $profile->subject, 'linked' => true], $client->ip, $client->userAgent));

            return $this->sessions->open($user, $providerId, $client);
        }
        if (!$this->settings->signUp) {
            $this->reject($providerId, 'no account matches this identity and sign-up is off', $client, SocialException::ACCOUNT_EXISTS);
        }
        if ($email === null) {
            throw new SocialException(SocialException::EMAIL_REQUIRED, 'The provider shared no email address; grant the email scope or use another provider.');
        }
        $user = $this->sessions->create($email, $profile->emailVerified, $profile->name);
        $this->accounts->link($user->id, $providerId, $profile, $tokens);
        $this->events->dispatch(new SocialEvent(AuditNames::SIGNED_UP, $user->id, $providerId, ['account_id' => $profile->subject], $client->ip, $client->userAgent));

        return $this->sessions->open($user, $providerId, $client);
    }

    /**
     * @return array<string, mixed>
     * @throws SocialException
     */
    private function link(string $providerId, Profile $profile, Tokens $tokens, string $userId, ?Account $account, ClientContext $client): array
    {
        $user = $this->sessions->find($userId);
        if (!$user instanceof User) {
            throw new SocialException(SocialException::TOKEN_INVALID, 'The session\'s user is gone.');
        }
        if ($account !== null && $account->userId !== $userId) {
            throw new SocialException(SocialException::ACCOUNT_LINKED, 'This ' . $providerId . ' account is linked to another user.');
        }
        if ($account === null) {
            $email = $profile->email === null ? null : EmailNormalizer::normalize($profile->email);
            if ($email !== null && $email !== $user->email && !$this->settings->allowsDifferentEmail($providerId)) {
                throw new SocialException(SocialException::EMAIL_MISMATCH, 'The provider account\'s email is not the account\'s; the provider does not allow another.');
            }
            $account = $this->accounts->link($userId, $providerId, $profile, $tokens);
            $this->events->dispatch(new SocialEvent(AuditNames::LINKED, $userId, $providerId, ['account_id' => $profile->subject, 'trusted' => false], $client->ip, $client->userAgent));
        } else {
            $this->accounts->update($account, $profile, $tokens);
        }

        return ['status' => 'linked', 'account' => $account->toArray()];
    }

    /**
     * On the proxy's stable origin: the preview callback a validly signed state names; null when the
     * state is this deployment's own or carries no proxy payload.
     *
     * @throws SocialException a forged payload
     */
    private function forwardTo(string $state, string $providerId): ?string
    {
        $parts = explode(self::PROXY_SEPARATOR, $state);
        if (count($parts) !== 3) {
            return null;
        }
        [$random, $payload, $signature] = $parts;
        if (!hash_equals(self::base64url($this->pepper->hash(self::PROXY_CONTEXT, $random . self::PROXY_SEPARATOR . $payload)), $signature)) {
            throw new SocialException(SocialException::STATE_INVALID, 'The state is not signed by a deployment of this application.');
        }
        $decoded = json_decode((string) base64_decode(strtr($payload, '-_', '+/'), true), true);
        $returnTo = is_array($decoded) && is_string($decoded['return_to'] ?? null) ? $decoded['return_to'] : null;
        if (!is_array($decoded) || ($decoded['provider'] ?? null) !== $providerId || !is_int($decoded['exp'] ?? null) || $decoded['exp'] < $this->clock->now()->getTimestamp()) {
            throw new SocialException(SocialException::STATE_INVALID, 'The state is for another provider or has expired.');
        }
        if ($returnTo === null || preg_match('#^https?://[^/?\#]+(?:/[^?\#]*)?/social/[^/?\#]+/callback$#', $returnTo) !== 1) {
            throw new SocialException(SocialException::STATE_INVALID, 'The state names no callback.');
        }

        // The preview's own callback: it completes the flow itself with its cache entry.
        return Settings::origin($returnTo) === Settings::origin($this->settings->baseUrl) ? null : $returnTo;
    }

    /**
     * @return array<string, mixed>
     * @throws SocialException
     */
    private function takeState(string $providerId, string $state): array
    {
        if ($state === '') {
            throw new SocialException(SocialException::STATE_INVALID, 'The callback carries no state.');
        }
        $key = self::key('state', $state);
        $entry = $this->cache->get($key);
        $this->cache->delete($key);
        if (!is_array($entry) || ($entry['provider'] ?? null) !== $providerId) {
            throw new SocialException(SocialException::STATE_INVALID, 'The state is unknown, used or expired.');
        }

        /** @var array<string, mixed> $entry */
        return $entry;
    }

    /**
     * @throws SocialException
     */
    private function redirectUri(?string $requested): string
    {
        $allowed = $this->settings->redirectUris;
        if ($requested === null || $requested === '') {
            return $allowed[0] ?? throw new SocialException(SocialException::REDIRECT_NOT_ALLOWED, 'No redirect_uri is configured; pass one of the allowed ones.');
        }
        if (!in_array($requested, $allowed, true)) {
            throw new SocialException(SocialException::REDIRECT_NOT_ALLOWED, 'redirect_uri is not one of the allowed ones.');
        }

        return $requested;
    }

    /**
     * @throws SocialException always
     */
    private function reject(string $providerId, string $reason, ClientContext $client, string $as = SocialException::PROVIDER_ERROR): never
    {
        $this->events->dispatch(new SocialEvent(AuditNames::REJECTED, null, $providerId, ['reason' => $reason], $client->ip, $client->userAgent));

        throw new SocialException($as, $reason);
    }

    private static function key(string $kind, string $value): string
    {
        return 'polaris.social.' . $kind . '.' . hash('sha256', $value);
    }

    private static function base64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
