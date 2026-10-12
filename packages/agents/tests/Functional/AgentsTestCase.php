<?php

declare(strict_types=1);

namespace Polaris\Agents\Tests\Functional;

use Override;
use Polaris\Agents\AgentException;
use Polaris\Agents\AgentsPlugin;
use Polaris\Agents\Capability;
use Polaris\Agents\ExecutionContext;
use Polaris\Agents\Tests\Support\AgentKey;
use Polaris\OAuth\Tests\Functional\OAuthTestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

use function count;
use function dirname;
use function in_array;
use function json_encode;

use const JSON_THROW_ON_ERROR;

/**
 * The agents routes through the pipeline (and, with `POLARIS_HARNESS`, through every host), with the
 * audit, admin and OAuth plugins under them and a few capabilities: one `low` (auto-approved, a
 * handler), one `high` (step-up), one with a `location` and one spent by an amount budget. The
 * recorded steps in tests/Contract/fixtures replay identically.
 */
abstract class AgentsTestCase extends OAuthTestCase
{
    protected const string APPROVE = 'https://app.polaris.test/agents/approve';
    protected const string LOCATION = 'https://host.polaris.test/invite';

    #[Override]
    protected static function plugins(): array
    {
        return [...parent::plugins(), new AgentsPlugin(
            baseUrl: self::BASE,
            capabilities: self::capabilities(),
            approvalUrl: self::APPROVE,
            providerName: 'Polaris test',
            description: 'The agents functional suite',
        )];
    }

    #[Override]
    protected static function fixtureDirectory(): string
    {
        return dirname(__DIR__) . '/Contract/fixtures';
    }

    /**
     * @return list<Capability>
     */
    protected static function capabilities(): array
    {
        $schema = static fn(array $properties, array $required = []): array => ['type' => 'object', 'properties' => $properties, 'required' => $required, 'additionalProperties' => false];

        return [
            new Capability('members.list', 'Count the members', $schema([]), 'members.read', 'low', handler: static fn(array $arguments, ExecutionContext $context): array => ['members' => 1, 'agent' => $context->agent->id]),
            new Capability('org.rename', 'Rename the organization', $schema(['name' => ['type' => 'string']], ['name']), 'org.update', 'high', handler: static fn(array $arguments): array => ['renamed' => $arguments['name']]),
            new Capability('audit.export', 'Export the audit log', $schema(['format' => ['type' => 'string']]), 'audit.read', 'medium', handler: static fn(array $arguments): array => ['format' => $arguments['format'] ?? 'json']),
            new Capability('credits.spend', 'Spend credits', $schema(['amount' => ['type' => 'number']], ['amount']), 'roles.manage', 'medium', handler: static fn(array $arguments): array => ['spent' => $arguments['amount']]),
            new Capability('invite', 'Invite a member at the host', $schema(['email' => ['type' => 'string']], ['email']), 'members.invite', 'medium', location: self::LOCATION),
        ];
    }

    /**
     * A JSON request signed with the agent's key: `Authorization: Bearer <agent+jwt>` for the exact URL.
     *
     * @param array<string, mixed>|null $body
     * @param array<string, mixed> $claims
     */
    protected function signed(AgentKey $key, string $agentId, string $method, string $path, ?array $body = null, array $claims = []): ResponseInterface
    {
        $request = $this->request($method, $path);
        if ($body !== null) {
            $request = $request->withHeader('Content-Type', 'application/json')->withParsedBody($body);
            $request->getBody()->write(json_encode($body, JSON_THROW_ON_ERROR));
            $request->getBody()->rewind();
        }

        return $this->handle($request->withHeader('Authorization', 'Bearer ' . $key->requestJwt($agentId, self::BASE . $path, $claims)));
    }

    /**
     * A JSON request with an OAuth access token (or any bearer) to a full URL.
     *
     * @param array<string, mixed>|null $body
     */
    protected function bearer(string $token, string $method, string $path, ?array $body = null): ResponseInterface
    {
        $request = $this->request($method, $path);
        if ($body !== null) {
            $request = $request->withHeader('Content-Type', 'application/json')->withParsedBody($body);
        }

        return $this->handle($request->withHeader('Authorization', 'Bearer ' . $token));
    }

    /**
     * @return array<string, mixed>
     */
    protected function agentsProblem(ResponseInterface $response, int $status, string $type, ?string $error = null, string $message = ''): array
    {
        self::assertSame($status, $response->getStatusCode(), $message . ' ' . $response->getBody());
        self::assertSame('application/problem+json', $response->getHeaderLine('Content-Type'), $message);
        $body = $this->json($response);
        self::assertSame('https://polaris.univeros.io/problems/agents/' . $type, $body['type'], $message);
        self::assertSame($error ?? (in_array($type, AgentException::PROTOCOL_CODES, true) ? $type : 'agents_' . $type), $body['error'], $message);

        return $body;
    }

    /**
     * Registers an agent for the session; its record.
     *
     * @param array<string, mixed> $fields
     * @return array<string, mixed>
     */
    protected function registerAgent(string $access, array $fields): array
    {
        $created = $this->authedPostJson('/agents/register', ['name' => 'Bot', 'mode' => 'delegated', 'auth' => 'client_secret', ...$fields], $access);
        self::assertSame(201, $created->getStatusCode(), (string) $created->getBody());

        return $this->json($created)['data'];
    }

    protected static function assertEventCount(int $expected, array $events, string $message = ''): void
    {
        self::assertSame($expected, count($events), $message);
    }

    protected function serverRequestFor(string $method, string $url): ServerRequestInterface
    {
        return (new \Laminas\Diactoros\ServerRequestFactory())->createServerRequest($method, $url);
    }
}
