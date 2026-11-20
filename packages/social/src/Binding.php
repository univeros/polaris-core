<?php

declare(strict_types=1);

namespace Polaris\Social;

use function hash;
use function hash_equals;
use function is_string;
use function sprintf;
use function str_starts_with;
use function substr;

/**
 * A flow is bound to the browser that started it: the start answers a cookie holding a random nonce
 * the state entry keeps, and the callback refuses a state whose browser does not present it, so a flow
 * started elsewhere cannot be completed in this browser.
 *
 * The cookie is named after the state, so flows in several tabs do not overwrite one another. Under an
 * https `baseUrl` it is `__Host-` prefixed (no sibling subdomain can set it) and `SameSite=None`, so a
 * `form_post` callback (Apple) carries it: the nonce is only compared with the state's, sending it
 * cross-site gives nothing away. Over plain http (local development) it is `SameSite=Lax`.
 */
final class Binding
{
    private const string PREFIX = 'polaris_social_';

    public function __construct(private readonly Settings $settings)
    {
    }

    public function cookieName(string $state): string
    {
        $name = self::PREFIX . substr(hash('sha256', $state), 0, 16);

        return $this->https() ? '__Host-' . $name : $name;
    }

    /**
     * The `Set-Cookie` value that hands the browser the flow's nonce, for as long as the state lives.
     */
    public function setCookie(string $state, string $nonce): string
    {
        return sprintf(
            '%s=%s; Path=/; Max-Age=%d; %s',
            $this->cookieName($state),
            $nonce,
            $this->settings->stateTtl,
            $this->https() ? 'HttpOnly; Secure; SameSite=None' : 'HttpOnly; SameSite=Lax',
        );
    }

    /**
     * Whether the browser's cookies hold the state's nonce (compared in constant time).
     *
     * @param array<string, mixed> $cookies the request's own cookies, never input merged with the query or body
     */
    public function bound(string $state, mixed $nonce, array $cookies): bool
    {
        $presented = $cookies[$this->cookieName($state)] ?? null;

        return is_string($nonce) && $nonce !== '' && is_string($presented) && hash_equals($nonce, $presented);
    }

    private function https(): bool
    {
        return str_starts_with($this->settings->baseUrl, 'https://');
    }
}
