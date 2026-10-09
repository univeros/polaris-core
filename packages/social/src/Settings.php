<?php

declare(strict_types=1);

namespace Polaris\Social;

use LogicException;

use function in_array;
use function parse_url;
use function preg_match;
use function rtrim;

use const PHP_URL_HOST;
use const PHP_URL_PORT;
use const PHP_URL_SCHEME;

/**
 * The plugin's configuration: where Polaris is mounted (the callbacks derive from it), the application
 * URLs a sign-in may end on, the linking policy, sign-up, and the stable origin of the OAuth proxy.
 */
final readonly class Settings
{
    public string $baseUrl;
    public ?string $proxy;
    /** @var list<string> */
    public array $redirectUris;
    /** @var list<string> */
    public array $trustedProviders;
    /** @var list<string> */
    public array $allowDifferentEmails;

    /**
     * @param list<string> $redirectUris exact URLs a sign-in may end on; the first is the default
     * @param list<string> $trustedProviders providers whose verified email links to an existing user by itself
     * @param list<string> $allowDifferentEmails providers that may be linked from a session with another email
     * @param string|null $proxy the stable origin registered at the providers, when this deployment is not it
     */
    public function __construct(
        string $baseUrl,
        array $redirectUris = [],
        array $trustedProviders = ['google', 'apple'],
        array $allowDifferentEmails = [],
        public bool $signUp = true,
        public bool $respectMfa = true,
        ?string $proxy = null,
        public int $stateTtl = 600,
    ) {
        if (preg_match('#^https?://[^/]+#', $baseUrl) !== 1) {
            throw new LogicException('baseUrl must be an absolute http(s) URL, where Polaris is mounted.');
        }
        if ($proxy !== null && preg_match('#^https?://[^/]+$#', rtrim($proxy, '/')) !== 1) {
            throw new LogicException('proxy must be an origin, such as https://auth.example.com.');
        }
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->proxy = $proxy === null ? null : rtrim($proxy, '/');
        $this->redirectUris = $redirectUris;
        $this->trustedProviders = $trustedProviders;
        $this->allowDifferentEmails = $allowDifferentEmails;
    }

    public function callbackUrl(string $provider): string
    {
        return $this->baseUrl . '/social/' . $provider . '/callback';
    }

    /**
     * Whether this deployment starts its flows through the proxy (its origin is not the stable one).
     */
    public function proxied(): bool
    {
        return $this->proxy !== null && self::origin($this->baseUrl) !== $this->proxy;
    }

    public function trusts(string $provider): bool
    {
        return in_array($provider, $this->trustedProviders, true);
    }

    public function allowsDifferentEmail(string $provider): bool
    {
        return in_array($provider, $this->allowDifferentEmails, true);
    }

    public static function origin(string $url): string
    {
        $port = parse_url($url, PHP_URL_PORT);

        return parse_url($url, PHP_URL_SCHEME) . '://' . parse_url($url, PHP_URL_HOST) . ($port === null ? '' : ':' . $port);
    }
}
