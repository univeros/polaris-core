<?php

declare(strict_types=1);

namespace Polaris\Social;

use Polaris\Social\Provider\AppleProvider;
use Polaris\Social\Provider\Catalog;
use Polaris\Social\Provider\Definition;
use Polaris\Social\Provider\GitHubProvider;
use Polaris\Social\Provider\Http;
use Polaris\Social\Provider\IdTokens;
use Polaris\Social\Provider\OAuth2Provider;
use Polaris\Social\Provider\Provider;
use Psr\Clock\ClockInterface;
use Psr\SimpleCache\CacheInterface;

use function array_keys;
use function array_values;
use function array_filter;
use function is_array;
use function is_string;
use function rtrim;
use function sprintf;

/**
 * The providers the host configured, by id: a catalog provider from its client credentials (Apple from
 * its team key), or any other OAuth 2 server from a {@see Definition} or from an OpenID Connect issuer
 * discovered at first use. Built once each.
 */
final class Providers
{
    /** @var array<string, Provider> */
    private array $built = [];

    /**
     * @param array<string, array<string, mixed>> $config provider id => `client_id`, `client_secret`, and for
     *   Apple `team_id`, `key_id`, `private_key`; for Microsoft `tenant`; for another server `definition`
     *   (a {@see Definition}) or `issuer` (OpenID Connect discovery), with `name` and `scopes`
     */
    public function __construct(
        private readonly array $config,
        private readonly Http $http,
        private readonly CacheInterface $cache,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * @return list<string>
     */
    public function ids(): array
    {
        return array_keys($this->config);
    }

    /**
     * @throws SocialException not configured, or misconfigured
     */
    public function get(string $id): Provider
    {
        if (isset($this->built[$id])) {
            return $this->built[$id];
        }
        $config = $this->config[$id] ?? null;
        if (!is_array($config)) {
            throw new SocialException(SocialException::PROVIDER_NOT_FOUND, sprintf('No provider "%s" is configured.', $id));
        }
        $clientId = $config['client_id'] ?? null;
        if (!is_string($clientId) || $clientId === '') {
            throw new SocialException(SocialException::PROVIDER_ERROR, sprintf('Provider "%s" has no client_id.', $id));
        }
        $secret = is_string($config['client_secret'] ?? null) && $config['client_secret'] !== '' ? $config['client_secret'] : null;
        $idTokens = new IdTokens($this->http, $this->cache);

        return $this->built[$id] = match (true) {
            $id === 'apple' => new AppleProvider(Catalog::definition('apple'), $clientId, (string) ($config['team_id'] ?? ''), (string) ($config['key_id'] ?? ''), (string) ($config['private_key'] ?? ''), $this->http, $idTokens, $this->clock),
            $id === 'github' => new GitHubProvider(Catalog::definition('github'), $clientId, $secret, $this->http, $idTokens),
            ($config['definition'] ?? null) instanceof Definition => new OAuth2Provider($config['definition'], $clientId, $secret, $this->http, $idTokens),
            is_string($config['issuer'] ?? null) => new OAuth2Provider($this->discovered($id, $config), $clientId, $secret, $this->http, $idTokens),
            default => new OAuth2Provider(Catalog::definition($id, $config), $clientId, $secret, $this->http, $idTokens),
        };
    }

    /**
     * A definition from an OpenID Connect issuer's discovery document (cached an hour).
     *
     * @param array<string, mixed> $config
     * @throws SocialException
     */
    private function discovered(string $id, array $config): Definition
    {
        $issuer = rtrim((string) $config['issuer'], '/');
        $key = 'polaris.social.discovery.' . hash('xxh128', $issuer) . '.document';
        $document = $this->cache->get($key);
        if (!is_array($document)) {
            $document = $this->http->json('GET', $issuer . '/.well-known/openid-configuration', null);
            $this->cache->set($key, $document, 3600);
        }
        foreach (['authorization_endpoint', 'token_endpoint'] as $required) {
            if (!is_string($document[$required] ?? null)) {
                throw new SocialException(SocialException::PROVIDER_ERROR, sprintf('The discovery document of "%s" names no %s.', $id, $required));
            }
        }
        $scopes = is_array($config['scopes'] ?? null) ? array_values(array_filter($config['scopes'], 'is_string')) : ['openid', 'email', 'profile'];

        return new Definition(
            $id,
            is_string($config['name'] ?? null) ? $config['name'] : $id,
            (string) $document['authorization_endpoint'],
            (string) $document['token_endpoint'],
            is_string($document['userinfo_endpoint'] ?? null) ? $document['userinfo_endpoint'] : null,
            $scopes,
            Catalog::oidcProfile(...),
            issuer: is_string($document['issuer'] ?? null) ? $document['issuer'] : $issuer,
            jwksUri: is_string($document['jwks_uri'] ?? null) ? $document['jwks_uri'] : null,
        );
    }
}
