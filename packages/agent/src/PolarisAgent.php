<?php

declare(strict_types=1);

namespace Polaris\Agent;

use Closure;
use LogicException;
use Polaris\Agent\Http\Transport;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

use function array_values;
use function base64_encode;
use function is_array;
use function is_string;
use function preg_replace_callback;
use function rawurlencode;
use function rtrim;
use function str_ends_with;

/**
 * An agent of a Polaris server: registers or enrols, asks for grants and waits for their approval,
 * executes capabilities with a signed request JWT (or an access token), mints tokens and verifies
 * receipts. Immutable: `bound()` and `withToken()` answer a new instance.
 */
final class PolarisAgent
{
    public const string TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
    public const string ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

    private readonly Transport $transport;
    /** @var array<string, mixed>|null */
    private ?array $jwks = null;

    /**
     * @param AgentKey|null $key signs the request JWTs and the `private_key_jwt` assertions
     * @param string|null $agentId once registered or enrolled (`bound()`)
     * @param string|null $accessToken an OAuth access token sent instead of request JWTs (`withToken()`)
     * @param string|null $clientSecret the `pcs_` secret of a `client_secret` agent, for `token()`
     * @param int $jwtTtl seconds a request JWT lives; at most 300
     * @param (Closure(): int)|null $now the clock, for tests
     * @param (Closure(int): void)|null $sleep the pause between approval polls, for tests
     */
    public function __construct(
        public readonly Configuration $configuration,
        private readonly ClientInterface $client,
        private readonly RequestFactoryInterface $requests,
        private readonly StreamFactoryInterface $streams,
        private readonly ?AgentKey $key = null,
        public readonly ?string $agentId = null,
        private readonly ?string $accessToken = null,
        private readonly ?string $clientSecret = null,
        private readonly int $jwtTtl = RequestJwt::DEFAULT_TTL,
        private readonly ?Closure $now = null,
        private readonly ?Closure $sleep = null,
    ) {
        $this->transport = new Transport($client, $requests, $streams);
    }

    /**
     * The discovery document at `<mount>/.well-known/agent-configuration` (the mount, or the document's own URL).
     *
     * @throws AgentException
     */
    public static function discover(string $url, ClientInterface $client, RequestFactoryInterface $requests, StreamFactoryInterface $streams): Configuration
    {
        $trimmed = rtrim($url, '/');
        $documentUrl = str_ends_with($trimmed, Routes::CONFIGURATION['path']) ? $trimmed : $trimmed . Routes::CONFIGURATION['path'];

        return new Configuration((new Transport($client, $requests, $streams))->send('GET', $documentUrl, null, []));
    }

    /** `discover()` then `new PolarisAgent()`, in one call. */
    public static function create(string $url, ClientInterface $client, RequestFactoryInterface $requests, StreamFactoryInterface $streams, ?AgentKey $key = null, ?string $agentId = null): self
    {
        return new self(self::discover($url, $client, $requests, $streams), $client, $requests, $streams, $key, $agentId);
    }

    /** The same agent, bound to its id (what `register()` and `enroll()` answer as `id`). */
    public function bound(string $agentId): self
    {
        return new self($this->configuration, $this->client, $this->requests, $this->streams, $this->key, $agentId, $this->accessToken, $this->clientSecret, $this->jwtTtl, $this->now, $this->sleep);
    }

    /** The same agent sending an access token (from `token()`) instead of request JWTs. */
    public function withToken(string $accessToken): self
    {
        return new self($this->configuration, $this->client, $this->requests, $this->streams, $this->key, $this->agentId, $accessToken, $this->clientSecret, $this->jwtTtl, $this->now, $this->sleep);
    }

    /**
     * `POST /agents/register` by the owner (`$ownerToken`: their access token): the agent's record, its
     * grants, the secret once, a pending approval. `bound($record['id'])` is the agent itself.
     *
     * @param array<string, mixed> $input `name`, `mode`, `auth` (private_key_jwt when the agent has a key, else client_secret), `organization_id`, `capabilities`
     * @return array<string, mixed>
     * @throws AgentException
     */
    public function register(string $ownerToken, array $input): array
    {
        return $this->data($this->post(Routes::REGISTER['path'], $this->registration($input), 'Bearer ' . $ownerToken));
    }

    /**
     * `POST /agents/enroll` through a host (`$enrollmentToken`: its `peh_...` token).
     *
     * @param array<string, mixed> $input `name`, `mode`, `auth`
     * @return array<string, mixed>
     * @throws AgentException
     */
    public function enroll(string $enrollmentToken, array $input): array
    {
        return $this->data($this->post(Routes::ENROLL['path'], $this->registration($input), 'Bearer ' . $enrollmentToken));
    }

    /**
     * `POST /agents/grants/request`: what the policy approves is active at once, the rest waits in `approval`.
     *
     * @param list<string|array<string, mixed>> $capabilities names, or `{name, constraints}`
     * @param array<string, mixed> $options `reason`, `preferred_method`, `binding_message`
     * @return array<string, mixed> `agent_id`, `agent_capability_grants`, `approval`
     * @throws AgentException
     */
    public function requestGrants(array $capabilities, array $options = []): array
    {
        return $this->post(Routes::REQUEST_GRANTS['path'], ['capabilities' => $capabilities, ...$options]);
    }

    /**
     * Polls the agent's session until the approval's grants are active.
     *
     * @param array<string, mixed> $approval
     * @param (callable(): bool)|null $cancelled
     * @return list<array<string, mixed>>
     * @throws ApprovalException denied, expired, cancelled
     * @throws AgentException
     */
    public function waitForApproval(array $approval, ?int $maxAttempts = null, ?callable $cancelled = null): array
    {
        return Approvals::wait($approval, fn(): array => $this->grants(), $this->sleep, $this->now, $maxAttempts, $cancelled);
    }

    /**
     * `POST /agents/execute`: the handler's result and the receipt appended to the agent's chain.
     *
     * @param array<string, mixed> $arguments
     * @param list<string>|null $capabilities the grants the request JWT may use
     * @return array<string, mixed> `data`, `receipt`
     * @throws AgentException
     */
    public function execute(string $capability, array $arguments = [], ?array $capabilities = null): array
    {
        return $this->post(Routes::EXECUTE['path'], ['capability' => $capability, 'arguments' => (object) $arguments], null, $capabilities);
    }

    /**
     * `GET /agents/session`: the agent, its owner, its host and its grants with their remaining budgets.
     *
     * @return array<string, mixed>
     * @throws AgentException
     */
    public function session(): array
    {
        return $this->data($this->get(Routes::SESSION['path']));
    }

    /**
     * `GET /agents/capabilities`, with `grant_status` when the agent authenticates.
     *
     * @return list<array<string, mixed>>
     * @throws AgentException
     */
    public function capabilities(): array
    {
        $url = $this->url(Routes::CAPABILITIES['path']);
        $headers = $this->agentId !== null && ($this->key !== null || $this->accessToken !== null) ? ['Authorization' => $this->credential('GET', $url)] : [];
        $capabilities = $this->transport->send('GET', $url, null, $headers)['data']['capabilities'] ?? [];

        return is_array($capabilities) ? array_values($capabilities) : [];
    }

    /**
     * A token from the OAuth token endpoint: client credentials for an autonomous agent, or the exchange
     * of a user's access token (`subject_token`) for a delegated one. The client authenticates with a
     * `private_key_jwt` assertion signed by the key, or with the client secret (HTTP Basic).
     *
     * @param array<string, mixed> $options `scope`, `resource`, `audience`, `subject_token`
     * @return array<string, mixed> the RFC 6749 token response
     * @throws AgentException
     */
    public function token(array $options = []): array
    {
        $agentId = $this->requireAgentId();
        $endpoint = $this->configuration->tokenEndpoint;
        $headers = [];
        $form = [];
        if ($this->key !== null) {
            $form['client_assertion_type'] = RequestJwt::ASSERTION_TYPE;
            $form['client_assertion'] = RequestJwt::assertion($this->key, $agentId, $endpoint, $this->now);
        } elseif ($this->clientSecret !== null) {
            $headers['Authorization'] = 'Basic ' . base64_encode($agentId . ':' . $this->clientSecret);
        } else {
            $form['client_id'] = $agentId;
        }
        $subject = $options['subject_token'] ?? null;
        if (is_string($subject)) {
            $form += ['grant_type' => self::TOKEN_EXCHANGE, 'subject_token' => $subject, 'subject_token_type' => self::ACCESS_TOKEN_TYPE];
        } else {
            $form['grant_type'] = 'client_credentials';
        }
        foreach (['scope', 'resource', 'audience'] as $name) {
            if (is_string($options[$name] ?? null)) {
                $form[$name] = $options[$name];
            }
        }

        return $this->transport->send('POST', $endpoint, Transport::encodeForm($form), $headers, 'application/x-www-form-urlencoded');
    }

    /**
     * Verifies a receipt locally against the server's JWKS (fetched once per agent), and its link to `$previous` when given.
     *
     * @param array<string, mixed> $receipt
     * @param array<string, mixed>|null $previous
     * @return array{valid: bool, checks: array{hash: bool, signature: bool, chain: bool}}
     * @throws AgentException
     */
    public function verifyReceipt(array $receipt, ?array $previous = null): array
    {
        $this->jwks ??= $this->transport->send('GET', $this->url(Routes::JWKS['path']), null, []);

        return Receipts::verify($receipt, $this->jwks, $previous);
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function grants(): array
    {
        $grants = $this->session()['grants'] ?? [];

        return is_array($grants) ? array_values($grants) : [];
    }

    /**
     * @param array<string, mixed> $input
     * @return array<string, mixed>
     */
    private function registration(array $input): array
    {
        $auth = $input['auth'] ?? ($this->key === null ? 'client_secret' : 'private_key_jwt');
        if ($auth === 'private_key_jwt' && $this->key === null) {
            throw new LogicException('private_key_jwt needs a key (AgentKey::generate()).');
        }

        return [...$input, 'auth' => $auth, ...($auth === 'private_key_jwt' ? ['jwk' => $this->key->publicJwk] : [])];
    }

    /**
     * @param array<string, mixed> $body
     * @param list<string>|null $capabilities
     * @return array<string, mixed>
     */
    private function post(string $path, array $body, ?string $authorization = null, ?array $capabilities = null): array
    {
        $url = $this->url($path);
        $encoded = Transport::encode($body);

        return $this->transport->send('POST', $url, $encoded, ['Authorization' => $authorization ?? $this->credential('POST', $url, $encoded, $capabilities)]);
    }

    /**
     * @return array<string, mixed>
     */
    private function get(string $path): array
    {
        $url = $this->url($path);

        return $this->transport->send('GET', $url, null, ['Authorization' => $this->credential('GET', $url)]);
    }

    /**
     * The bearer for a call: a request JWT for its exact URL and body when the agent has a key, else its access token.
     *
     * @param list<string>|null $capabilities
     */
    private function credential(string $method, string $url, ?string $body = null, ?array $capabilities = null): string
    {
        if ($this->accessToken !== null) {
            return 'Bearer ' . $this->accessToken;
        }
        if ($this->key === null) {
            throw new LogicException('The agent has no key and no access token; give it one of them.');
        }

        return 'Bearer ' . RequestJwt::sign($this->key, $this->requireAgentId(), $method, $url, $body, $capabilities, $this->jwtTtl, $this->now);
    }

    /**
     * @param array<string, string> $params
     */
    private function url(string $path, array $params = []): string
    {
        $filled = preg_replace_callback('/\{(\w+)\}/', static function (array $match) use ($params): string {
            if (!isset($params[$match[1]])) {
                throw new LogicException('The route needs ' . $match[1] . '.');
            }

            return rawurlencode($params[$match[1]]);
        }, $path);

        return $this->configuration->mount . $filled;
    }

    /**
     * @param array<string, mixed> $answer
     * @return array<string, mixed>
     */
    private function data(array $answer): array
    {
        return is_array($answer['data'] ?? null) ? $answer['data'] : [];
    }

    private function requireAgentId(): string
    {
        if ($this->agentId === null) {
            throw new LogicException('The agent is not registered yet: register or enroll it and bind its id, or give its agentId.');
        }

        return $this->agentId;
    }
}
