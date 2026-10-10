<?php

declare(strict_types=1);

namespace Polaris\OAuth;

use DateTimeImmutable;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT as FirebaseJwt;
use Polaris\Contract\DatabaseAdapter;
use Polaris\OAuth\Model\Client;
use Polaris\Security\Pepper;
use Psr\Clock\ClockInterface;
use Psr\SimpleCache\CacheInterface;
use Symfony\Component\Uid\Uuid;
use Throwable;

use function array_filter;
use function array_key_exists;
use function array_intersect;
use function array_is_list;
use function array_unique;
use function array_values;
use function explode;
use function filter_var;
use function hash;
use function in_array;
use function is_array;
use function is_bool;
use function is_int;
use function is_string;
use function json_decode;
use function json_encode;
use function lcfirst;
use function max;
use function min;
use function mb_strlen;
use function parse_url;
use function preg_match;
use function random_bytes;
use function rtrim;
use function sprintf;
use function str_contains;
use function str_ends_with;
use function str_starts_with;
use function strtolower;
use function trim;

use const FILTER_FLAG_IPV4;
use const FILTER_FLAG_IPV6;
use const FILTER_FLAG_NO_PRIV_RANGE;
use const FILTER_FLAG_NO_RES_RANGE;
use const FILTER_VALIDATE_IP;
use const JSON_THROW_ON_ERROR;
use const PHP_URL_HOST;
use const PHP_URL_PATH;
use const PHP_URL_SCHEME;

/**
 * The clients: registered ones (`polaris_oauth_client`, by an organization, an operator or dynamic
 * registration) and the ones described by a client ID metadata document (an `https` `client_id`,
 * fetched, validated and cached, never stored); their secrets as keyed hashes; and their
 * authentication at the token endpoint by secret, Basic, signed assertion or none.
 */
final class Clients
{
    public const string GRANT_CODE = 'authorization_code';
    public const string GRANT_REFRESH = 'refresh_token';
    public const string GRANT_CLIENT = 'client_credentials';
    public const string GRANT_DEVICE = 'urn:ietf:params:oauth:grant-type:device_code';
    public const string GRANT_CIBA = 'urn:openid:params:grant-type:ciba';
    public const string GRANT_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
    public const array GRANTS = [self::GRANT_CODE, self::GRANT_REFRESH, self::GRANT_CLIENT, self::GRANT_DEVICE, self::GRANT_CIBA, self::GRANT_EXCHANGE];
    public const array AUTH_METHODS = [Client::AUTH_SECRET_BASIC, Client::AUTH_SECRET_POST, Client::AUTH_PRIVATE_KEY_JWT, Client::AUTH_NONE];
    private const array ASSERTION_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA'];
    private const string PEPPER_CONTEXT = 'oauth_client';
    private const string METADATA_CACHE = 'polaris.oauth.cimd.';
    private const string JWKS_CACHE = 'polaris.oauth.jwks.';
    private const string ASSERTION_CACHE = 'polaris.oauth.assertion.';
    private const int METADATA_TTL = 3600;
    private const array SPECIAL_HOSTS = ['localhost', '.localhost', '.local', '.internal', '.home.arpa', '.onion', '.test', '.example', '.invalid', '.arpa'];

    public function __construct(
        private readonly DatabaseAdapter $database,
        private readonly Pepper $pepper,
        private readonly Scopes $scopes,
        private readonly Settings $settings,
        private readonly Fetch $fetch,
        private readonly CacheInterface $cache,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * The client a `client_id` names: a registered one, or the one its metadata document describes.
     */
    public function find(string $clientId): ?Client
    {
        $row = $this->database->findOne(Schema::CLIENTS, ['client_id' => $clientId]);
        if ($row !== null) {
            return self::hydrate($row);
        }
        if (str_starts_with($clientId, 'https://')) {
            return $this->fromMetadata($clientId);
        }

        return null;
    }

    public function findById(string $id): ?Client
    {
        $row = $this->database->findOne(Schema::CLIENTS, ['id' => $id]);

        return $row === null ? null : self::hydrate($row);
    }

    /**
     * @return list<Client>
     */
    public function forOrganization(string $organizationId): array
    {
        return $this->list(['organization_id' => $organizationId]);
    }

    /**
     * @return list<Client>
     */
    public function all(): array
    {
        return $this->list([]);
    }

    /**
     * @param array<string, mixed> $fields the registration (`name`, `type`, `redirect_uris`, `grant_types`, `scopes`, `token_endpoint_auth_method`, `jwks`, `jwks_uri`, `dpop_bound_access_tokens`, `trusted`, `logo_uri`, `client_uri`, `policy_uri`, `tos_uri`)
     * @param bool $mayTrust whether `trusted` is honoured (operators), or ignored (organizations, dynamic registration)
     */
    public function create(array $fields, ?string $organizationId, ?string $createdBy, bool $mayTrust): IssuedClient
    {
        $now = $this->clock->now();
        $client = new Client();
        $client->id = Uuid::v7()->toRfc4122();
        // A UUID, so a client id in a path (`/oauth2/consents/{clientId}`) reads like every other id.
        $client->clientId = Uuid::v7()->toRfc4122();
        $client->organizationId = $organizationId;
        $client->createdBy = $createdBy;
        $client->createdAt = $now;
        $client->updatedAt = $now;
        $this->apply($client, $fields, $mayTrust, true);
        $secret = null;
        if (in_array($client->tokenEndpointAuthMethod, [Client::AUTH_SECRET_BASIC, Client::AUTH_SECRET_POST], true)) {
            $secret = 'pcs_' . Jwt::base64UrlEncode(random_bytes(32));
            $client->secretHash = $this->pepper->hash(self::PEPPER_CONTEXT, $secret);
        }
        $this->database->insert(Schema::CLIENTS, $this->row($client));

        return new IssuedClient($client, $secret);
    }

    /**
     * @param array<string, mixed> $fields
     * @return list<string> what changed
     */
    public function update(Client $client, array $fields, bool $mayTrust): array
    {
        if ($client->isMetadataClient()) {
            throw new OAuthException(OAuthException::INVALID_REQUEST, 'A client described by its metadata document is not managed here.');
        }
        $before = $client->toArray();
        $this->apply($client, $fields, $mayTrust, false);
        $client->updatedAt = $this->clock->now();
        $changes = [];
        foreach ($client->toArray() as $key => $value) {
            if ($key !== 'updated_at' && ($before[$key] ?? null) !== $value) {
                $changes[] = $key;
            }
        }
        $this->database->update(Schema::CLIENTS, ['id' => $client->id], $this->row($client));

        return $changes;
    }

    public function delete(Client $client): void
    {
        $this->database->delete(Schema::CLIENTS, ['id' => $client->id]);
    }

    public function deleteForOrganization(string $organizationId): void
    {
        $this->database->delete(Schema::CLIENTS, ['organization_id' => $organizationId]);
    }

    /**
     * The client the credentials authenticate, by the method it registered with.
     *
     * @param string $audience the endpoint URL a signed assertion must name (or the issuer)
     * @throws OAuthException `invalid_client` (401) or `invalid_request`
     */
    public function authenticate(ClientCredentials $credentials, string $audience, string $issuer): Client
    {
        if ($credentials->assertion !== null) {
            return $this->authenticateByAssertion($credentials, $audience, $issuer);
        }
        if ($credentials->clientId === null) {
            throw new OAuthException(OAuthException::INVALID_CLIENT, 'client_id is required.', 401);
        }
        $client = $this->find($credentials->clientId);
        if ($client === null || $client->disabledAt !== null) {
            throw new OAuthException(OAuthException::INVALID_CLIENT, 'Unknown client.', 401);
        }
        $method = $client->tokenEndpointAuthMethod;
        if ($credentials->secret !== null) {
            $expected = $credentials->basic ? Client::AUTH_SECRET_BASIC : Client::AUTH_SECRET_POST;
            if ($method !== $expected || $client->secretHash === null || !$this->pepper->matches(self::PEPPER_CONTEXT, $credentials->secret, $client->secretHash)) {
                throw new OAuthException(OAuthException::INVALID_CLIENT, 'The client secret does not match, or the client does not authenticate this way.', 401);
            }

            return $client;
        }
        if ($method !== Client::AUTH_NONE) {
            throw new OAuthException(OAuthException::INVALID_CLIENT, 'The client must authenticate with ' . $method . '.', 401);
        }

        return $client;
    }

    /**
     * The client a metadata document at `$url` describes (the MCP 2026 profile): fetched over HTTPS
     * from a public host, validated, cached for an hour.
     *
     * @throws OAuthException `invalid_client_metadata`
     */
    public function fromMetadata(string $url): Client
    {
        if (!$this->settings->clientIdMetadata) {
            throw new OAuthException(OAuthException::INVALID_CLIENT, 'Client ID metadata documents are not accepted here.', 401);
        }
        self::assertPublicHttpsUrl($url);
        $key = self::METADATA_CACHE . hash('sha256', $url);
        $document = $this->cache->get($key);
        $fetched = !is_array($document);
        if ($fetched) {
            $document = $this->fetch->json($url, OAuthException::INVALID_CLIENT_METADATA);
            if (($document['client_id'] ?? null) !== $url) {
                throw new OAuthException(OAuthException::INVALID_CLIENT_METADATA, 'The document\'s client_id must be its own URL.');
            }
        }
        $client = new Client();
        $client->clientId = $url;
        $client->createdAt = $this->clock->now();
        $client->updatedAt = $client->createdAt;
        $fields = ['name' => $document['client_name'] ?? $url, ...$document];
        unset($fields['client_id'], $fields['client_name'], $fields['trusted']);
        $fields['type'] = ($document['token_endpoint_auth_method'] ?? Client::AUTH_NONE) === Client::AUTH_NONE ? Client::TYPE_PUBLIC : Client::TYPE_CONFIDENTIAL;
        $fields['token_endpoint_auth_method'] = $document['token_endpoint_auth_method'] ?? Client::AUTH_NONE;
        try {
            $this->apply($client, $fields, false, true);
        } catch (OAuthException $exception) {
            throw new OAuthException(OAuthException::INVALID_CLIENT_METADATA, $exception->description);
        }
        if (!in_array($client->tokenEndpointAuthMethod, [Client::AUTH_NONE, Client::AUTH_PRIVATE_KEY_JWT], true)) {
            throw new OAuthException(OAuthException::INVALID_CLIENT_METADATA, 'A metadata client authenticates with none or private_key_jwt.');
        }
        if ($fetched) {
            // Cached once it validated, so a bad document is not served from the cache.
            $this->cache->set($key, $document, self::METADATA_TTL);
        }

        return $client;
    }

    /**
     * @throws OAuthException `invalid_client_metadata`
     */
    public static function assertPublicHttpsUrl(string $url, string $what = 'A client ID metadata URL'): void
    {
        $host = parse_url($url, PHP_URL_HOST);
        $port = parse_url($url, PHP_URL_PORT);
        if (parse_url($url, PHP_URL_SCHEME) !== 'https' || !is_string($host) || $host === '' || !is_string(parse_url($url, PHP_URL_PATH)) || preg_match('/[#@]/', $url) === 1 || ($port !== null && $port !== 443)) {
            throw new OAuthException(OAuthException::INVALID_CLIENT_METADATA, $what . ' is https on port 443, with a host and a path, without credentials or a fragment.');
        }
        $host = strtolower(rtrim(trim($host, '[]'), '.'));
        // A numeric host in any spelling (`2130706433`, `0x7f.1`, `0177.0.0.1`) is an address a resolver would
        // read differently from this check; only dotted-quad and IPv6 literals are judged, the rest refused.
        $numeric = preg_match('/^(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+))*$/i', $host) === 1;
        if ($numeric || filter_var($host, FILTER_VALIDATE_IP) !== false) {
            $public = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
            if (!$public || str_starts_with($host, '::ffff:') || ($numeric && preg_match('/^(\d{1,3}\.){3}\d{1,3}$/', $host) !== 1)) {
                throw new OAuthException(OAuthException::INVALID_CLIENT_METADATA, 'A special-use or numeric address cannot host ' . lcfirst($what) . '.');
            }

            return;
        }
        foreach (self::SPECIAL_HOSTS as $special) {
            if ($host === trim($special, '.') || str_ends_with($host, $special)) {
                throw new OAuthException(OAuthException::INVALID_CLIENT_METADATA, 'A special-use name cannot host ' . lcfirst($what) . '.');
            }
        }
    }

    /**
     * @param array<string, mixed> $fields
     * @throws OAuthException `invalid_client_metadata`
     */
    private function apply(Client $client, array $fields, bool $mayTrust, bool $creating): void
    {
        $invalid = static fn(string $detail): OAuthException => new OAuthException(OAuthException::INVALID_CLIENT_METADATA, $detail, 400);
        if (isset($fields['name']) || $creating) {
            $name = trim((string) ($fields['name'] ?? ''));
            if ($name === '' || mb_strlen($name) > 160) {
                throw $invalid('name is required, at most 160 characters.');
            }
            $client->name = $name;
        }
        if (isset($fields['type']) || $creating) {
            $type = $fields['type'] ?? Client::TYPE_CONFIDENTIAL;
            if (!in_array($type, [Client::TYPE_CONFIDENTIAL, Client::TYPE_PUBLIC], true)) {
                throw $invalid('type is confidential or public.');
            }
            $client->type = $type;
        }
        if (isset($fields['redirect_uris'])) {
            $client->redirectUris = self::uris($fields['redirect_uris'], 'redirect_uris', true, $invalid);
        }
        if (isset($fields['grant_types']) || $creating) {
            $grants = $fields['grant_types'] ?? [self::GRANT_CODE, self::GRANT_REFRESH];
            if (!is_array($grants) || !array_is_list($grants)) {
                throw $invalid('grant_types is a list.');
            }
            foreach ($grants as $grant) {
                if (!in_array($grant, self::GRANTS, true)) {
                    throw $invalid(sprintf('Unsupported grant type "%s".', is_string($grant) ? $grant : '?'));
                }
            }
            $client->grantTypes = array_values(array_unique($grants));
        }
        if (isset($fields['scopes']) || (isset($fields['scope']) && $creating)) {
            $scopes = $fields['scopes'] ?? explode(' ', (string) $fields['scope']);
            if (!is_array($scopes) || !array_is_list($scopes)) {
                throw $invalid('scopes is a list.');
            }
            $known = $this->scopes->all();
            foreach ($scopes as $scope) {
                if (!is_string($scope) || !isset($known[$scope])) {
                    throw $invalid(sprintf('Unknown scope "%s".', is_string($scope) ? $scope : '?'));
                }
            }
            $client->scopes = array_values(array_unique(array_filter($scopes, is_string(...))));
        }
        if (isset($fields['token_endpoint_auth_method']) || $creating) {
            $method = $fields['token_endpoint_auth_method'] ?? ($client->type === Client::TYPE_PUBLIC ? Client::AUTH_NONE : Client::AUTH_SECRET_BASIC);
            if (!in_array($method, self::AUTH_METHODS, true)) {
                throw $invalid('token_endpoint_auth_method is client_secret_basic, client_secret_post, private_key_jwt or none.');
            }
            $client->tokenEndpointAuthMethod = $method;
        }
        if (array_key_exists('jwks', $fields)) {
            $jwks = $fields['jwks'];
            if ($jwks !== null && (!is_array($jwks) || !is_array($jwks['keys'] ?? null))) {
                throw $invalid('jwks is a JWK Set with keys.');
            }
            $client->jwks = $jwks;
        }
        if (array_key_exists('jwks_uri', $fields)) {
            $jwksUri = $fields['jwks_uri'];
            if ($jwksUri !== null) {
                if (!is_string($jwksUri)) {
                    throw $invalid('jwks_uri is a URL.');
                }
                self::assertPublicHttpsUrl($jwksUri, 'jwks_uri');
            }
            $client->jwksUri = $jwksUri;
        }
        foreach (['logo_uri' => 'logoUri', 'client_uri' => 'clientUri', 'policy_uri' => 'policyUri', 'tos_uri' => 'tosUri'] as $field => $property) {
            if (array_key_exists($field, $fields)) {
                $client->{$property} = $fields[$field] === null ? null : self::uris([$fields[$field]], $field, false, $invalid)[0];
            }
        }
        if (isset($fields['dpop_bound_access_tokens'])) {
            if (!is_bool($fields['dpop_bound_access_tokens'])) {
                throw $invalid('dpop_bound_access_tokens is a boolean.');
            }
            $client->dpopBound = $fields['dpop_bound_access_tokens'];
        }
        if ($mayTrust && isset($fields['trusted'])) {
            if (!is_bool($fields['trusted'])) {
                throw $invalid('trusted is a boolean.');
            }
            $client->trusted = $fields['trusted'];
        }
        if (array_key_exists('disabled', $fields) && !$creating) {
            $client->disabledAt = $fields['disabled'] === true ? $this->clock->now() : null;
        }
        // Consistency.
        if ($client->type === Client::TYPE_PUBLIC && $client->tokenEndpointAuthMethod !== Client::AUTH_NONE) {
            throw $invalid('A public client authenticates with none.');
        }
        if ($client->type === Client::TYPE_CONFIDENTIAL && $client->tokenEndpointAuthMethod === Client::AUTH_NONE) {
            throw $invalid('A confidential client needs a secret or a key.');
        }
        if ($client->tokenEndpointAuthMethod === Client::AUTH_PRIVATE_KEY_JWT && $client->jwks === null && $client->jwksUri === null) {
            throw $invalid('private_key_jwt needs jwks or jwks_uri.');
        }
        if ($client->type === Client::TYPE_PUBLIC && in_array(self::GRANT_CLIENT, $client->grantTypes, true)) {
            throw $invalid('A public client cannot use client_credentials.');
        }
        if (in_array(self::GRANT_CODE, $client->grantTypes, true) && $client->redirectUris === []) {
            throw $invalid('redirect_uris is required for the authorization_code grant.');
        }
        if ($client->dpopBound && $this->settings->dpop === Settings::DPOP_OFF) {
            throw $invalid('DPoP is off on this server.');
        }
        if (!$mayTrust && in_array(self::GRANT_CIBA, $client->grantTypes, true)) {
            throw $invalid('The backchannel grant (CIBA) reaches people by name; an operator grants it.');
        }
        if ($client->isMetadataClient() && array_intersect($client->grantTypes, [self::GRANT_CLIENT, self::GRANT_EXCHANGE]) !== []) {
            throw $invalid('A client described by a metadata document may only act for a user (authorization_code, refresh_token, device_code).');
        }
    }

    /**
     * @param callable(string): OAuthException $invalid
     * @return list<string>
     */
    private static function uris(mixed $uris, string $field, bool $redirect, callable $invalid): array
    {
        if (!is_array($uris) || !array_is_list($uris)) {
            throw $invalid($field . ' is a list of URIs.');
        }
        $out = [];
        foreach ($uris as $uri) {
            if (!is_string($uri) || preg_match('~^[a-z][a-z0-9+.-]*://[^\s#]+$~i', $uri) !== 1) {
                throw $invalid($field . ' holds absolute URIs without a fragment.');
            }
            $scheme = strtolower((string) parse_url($uri, PHP_URL_SCHEME));
            $host = strtolower((string) parse_url($uri, PHP_URL_HOST));
            if ($scheme === 'http' && !in_array($host, ['localhost', '127.0.0.1', '[::1]'], true)) {
                throw $invalid($field . ': http is accepted for loopback only; use https.');
            }
            if (!$redirect && $scheme !== 'https') {
                throw $invalid($field . ' must be https.');
            }
            // A redirect URI is https, http on loopback, or an application's own reverse-domain scheme
            // (`com.example.app:/cb`); a scheme a browser would run or open (`javascript`, `data`, ...) is not.
            if ($redirect && !in_array($scheme, ['https', 'http'], true) && (!str_contains($scheme, '.') || in_array($scheme, ['javascript', 'data', 'vbscript', 'file', 'blob', 'about'], true))) {
                throw $invalid($field . ': a custom scheme must be a reverse-domain name such as com.example.app.');
            }
            $out[] = $uri;
        }

        return array_values(array_unique($out));
    }

    /**
     * @throws OAuthException
     */
    private function authenticateByAssertion(ClientCredentials $credentials, string $audience, string $issuer): Client
    {
        if ($credentials->assertionType !== ClientCredentials::ASSERTION_TYPE) {
            throw new OAuthException(OAuthException::INVALID_CLIENT, 'client_assertion_type must be ' . ClientCredentials::ASSERTION_TYPE . '.', 401);
        }
        $assertion = (string) $credentials->assertion;
        $header = Jwt::header($assertion);
        $parts = explode('.', $assertion);
        $unverified = json_decode(Jwt::base64UrlDecode($parts[1] ?? ''), true);
        $clientId = is_array($unverified) && is_string($unverified['iss'] ?? null) ? $unverified['iss'] : null;
        if ($header === null || $clientId === null || ($credentials->clientId !== null && $credentials->clientId !== $clientId)) {
            throw new OAuthException(OAuthException::INVALID_CLIENT, 'The client assertion is not a JWT naming the client as its issuer.', 401);
        }
        $client = $this->find($clientId);
        if ($client === null || $client->disabledAt !== null || $client->tokenEndpointAuthMethod !== Client::AUTH_PRIVATE_KEY_JWT) {
            throw new OAuthException(OAuthException::INVALID_CLIENT, 'Unknown client, or one that does not authenticate with a key.', 401);
        }
        if (!Jwt::supportsAlgorithm($header['alg'] ?? null, self::ASSERTION_ALGORITHMS)) {
            throw new OAuthException(OAuthException::INVALID_CLIENT, 'The assertion must be signed with an asymmetric algorithm.', 401);
        }
        try {
            FirebaseJwt::$leeway = 60;
            FirebaseJwt::$timestamp = $this->clock->now()->getTimestamp();
            $claims = (array) FirebaseJwt::decode($assertion, JWK::parseKeySet($this->jwks($client), (string) $header['alg']));
        } catch (Throwable $exception) {
            throw new OAuthException(OAuthException::INVALID_CLIENT, 'The client assertion does not verify: ' . $exception->getMessage(), 401);
        }
        $aud = $claims['aud'] ?? null;
        $audiences = is_array($aud) ? $aud : [$aud];
        if (($claims['sub'] ?? null) !== $clientId || (!in_array($audience, $audiences, true) && !in_array($issuer, $audiences, true)) || !is_int($claims['exp'] ?? null)) {
            throw new OAuthException(OAuthException::INVALID_CLIENT, 'The client assertion needs sub = the client, aud = this endpoint or issuer, and exp.', 401);
        }
        $jti = is_string($claims['jti'] ?? null) ? $claims['jti'] : '';
        $replayKey = self::ASSERTION_CACHE . hash('sha256', $clientId . '|' . $jti);
        if ($jti === '' || $this->cache->get($replayKey) !== null) {
            throw new OAuthException(OAuthException::INVALID_CLIENT, 'The client assertion needs a jti, and one not used before.', 401);
        }
        $this->cache->set($replayKey, 1, min(600, max(60, $claims['exp'] - $this->clock->now()->getTimestamp() + 60)));

        return $client;
    }

    /**
     * The client's keys: inline, or fetched from its `jwks_uri` and cached for an hour.
     *
     * @return array{keys: list<array<string, mixed>>}
     */
    private function jwks(Client $client): array
    {
        if ($client->jwks !== null && is_array($client->jwks['keys'] ?? null)) {
            /** @var array{keys: list<array<string, mixed>>} $jwks */
            $jwks = $client->jwks;

            return $jwks;
        }
        $uri = (string) $client->jwksUri;
        self::assertPublicHttpsUrl($uri, 'jwks_uri');
        $key = self::JWKS_CACHE . hash('sha256', $uri);
        $cached = $this->cache->get($key);
        if (is_array($cached) && is_array($cached['keys'] ?? null)) {
            /** @var array{keys: list<array<string, mixed>>} $cached */
            return $cached;
        }
        $document = $this->fetch->json($uri, OAuthException::INVALID_CLIENT);
        if (!is_array($document['keys'] ?? null)) {
            throw new OAuthException(OAuthException::INVALID_CLIENT, 'jwks_uri did not answer a JWK Set.', 401);
        }
        $this->cache->set($key, $document, self::METADATA_TTL);
        /** @var array{keys: list<array<string, mixed>>} $document */
        return $document;
    }

    /**
     * @param array<string, mixed> $criteria
     * @return list<Client>
     */
    private function list(array $criteria): array
    {
        $clients = [];
        foreach ($this->database->findMany(Schema::CLIENTS, $criteria, ['id' => 'asc']) as $row) {
            $clients[] = self::hydrate($row);
        }

        return $clients;
    }

    /**
     * @return array<string, mixed>
     */
    private function row(Client $client): array
    {
        return [
            'id' => $client->id,
            'client_id' => $client->clientId,
            'organization_id' => $client->organizationId,
            'name' => $client->name,
            'type' => $client->type,
            'secret_hash' => $client->secretHash,
            'redirect_uris' => json_encode($client->redirectUris, JSON_THROW_ON_ERROR),
            'grant_types' => json_encode($client->grantTypes, JSON_THROW_ON_ERROR),
            'scopes' => json_encode($client->scopes, JSON_THROW_ON_ERROR),
            'token_endpoint_auth_method' => $client->tokenEndpointAuthMethod,
            'jwks' => $client->jwks === null ? null : json_encode($client->jwks, JSON_THROW_ON_ERROR),
            'jwks_uri' => $client->jwksUri,
            'dpop_bound' => $client->dpopBound,
            'trusted' => $client->trusted,
            'logo_uri' => $client->logoUri,
            'client_uri' => $client->clientUri,
            'policy_uri' => $client->policyUri,
            'tos_uri' => $client->tosUri,
            'created_by' => $client->createdBy,
            'disabled_at' => $client->disabledAt,
            'created_at' => $client->createdAt,
            'updated_at' => $client->updatedAt,
        ];
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function hydrate(array $row): Client
    {
        $client = new Client();
        $client->id = (string) $row['id'];
        $client->clientId = (string) $row['client_id'];
        $client->organizationId = self::nullable($row['organization_id'] ?? null);
        $client->name = (string) $row['name'];
        $client->type = (string) $row['type'];
        $client->secretHash = self::nullable($row['secret_hash'] ?? null);
        $client->redirectUris = self::strings($row['redirect_uris'] ?? null);
        $client->grantTypes = self::strings($row['grant_types'] ?? null);
        $client->scopes = self::strings($row['scopes'] ?? null);
        $client->tokenEndpointAuthMethod = (string) $row['token_endpoint_auth_method'];
        $jwks = is_string($row['jwks'] ?? null) ? json_decode($row['jwks'], true) : ($row['jwks'] ?? null);
        $client->jwks = is_array($jwks) ? $jwks : null;
        $client->jwksUri = self::nullable($row['jwks_uri'] ?? null);
        $client->dpopBound = (bool) ($row['dpop_bound'] ?? false);
        $client->trusted = (bool) ($row['trusted'] ?? false);
        $client->logoUri = self::nullable($row['logo_uri'] ?? null);
        $client->clientUri = self::nullable($row['client_uri'] ?? null);
        $client->policyUri = self::nullable($row['policy_uri'] ?? null);
        $client->tosUri = self::nullable($row['tos_uri'] ?? null);
        $client->createdBy = self::nullable($row['created_by'] ?? null);
        $client->disabledAt = self::datetime($row['disabled_at'] ?? null);
        $client->createdAt = self::datetime($row['created_at']) ?? new DateTimeImmutable();
        $client->updatedAt = self::datetime($row['updated_at']) ?? $client->createdAt;

        return $client;
    }

    /**
     * @return list<string>
     */
    private static function strings(mixed $value): array
    {
        $decoded = is_string($value) ? json_decode($value, true) : $value;

        return is_array($decoded) ? array_values(array_filter($decoded, is_string(...))) : [];
    }

    private static function nullable(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    private static function datetime(mixed $value): ?DateTimeImmutable
    {
        if ($value === null || $value === '') {
            return null;
        }

        return $value instanceof DateTimeImmutable ? $value : new DateTimeImmutable((string) $value);
    }
}
