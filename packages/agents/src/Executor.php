<?php

declare(strict_types=1);

namespace Polaris\Agents;

use Opis\JsonSchema\Errors\ErrorFormatter;
use Opis\JsonSchema\Validator;
use Polaris\Agents\Event\AgentEvent;
use Polaris\Agents\Model\Agent;
use Polaris\Agents\Model\Grant;
use Polaris\Agents\Model\Receipt;
use Polaris\Contract\DatabaseAdapter;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use stdClass;

use function array_is_list;
use function array_map;
use function array_slice;
use function in_array;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use function sprintf;

use const JSON_THROW_ON_ERROR;

/**
 * One execution path for `POST /agents/execute`, the capabilities with a `location` (through
 * {@see Http\AgentRequestMiddleware}) and the MCP tools: the grant must be live for the capability
 * (and within the credential's capabilities and scopes), the owner must still hold the permission, the
 * arguments must satisfy the schema and the constraints; then, in one transaction, the budget is spent by
 * a conditional update, the handler runs and the receipt is appended. Every refusal is an
 * `agent.execution_denied` event, every execution an `agent.executed` one.
 */
final class Executor
{
    private const int MAX_ERRORS = 10;
    /** The keywords whose value is an object, so an empty PHP array under them is `{}` rather than `[]`. */
    private const array OBJECT_KEYWORDS = ['properties', 'patternProperties', '$defs', 'definitions', 'dependentSchemas', 'items', 'additionalProperties', 'not', 'if', 'then', 'else', 'contains', 'propertyNames', 'unevaluatedProperties', 'unevaluatedItems'];

    public function __construct(
        private readonly Capabilities $capabilities,
        private readonly Grants $grants,
        private readonly Receipts $receipts,
        private readonly DatabaseAdapter $database,
        private readonly EventDispatcherInterface $events,
        private readonly ClockInterface $clock,
        private readonly Validator $validator = new Validator(),
    ) {
    }

    /**
     * The checks before anything is spent.
     *
     * @throws AgentException `capability_not_found`, `capability_not_granted`, `invalid_arguments`, `constraint_violated`
     */
    public function evaluate(AuthenticatedAgent $principal, string $name, mixed $arguments): Evaluation
    {
        $capability = $this->capabilities->find($name);
        if ($capability === null) {
            throw new AgentException(AgentException::CAPABILITY_NOT_FOUND, sprintf('Unknown capability "%s".', $name));
        }
        if (!$principal->mayUse($name)) {
            throw new AgentException(AgentException::CAPABILITY_NOT_GRANTED, 'The request JWT does not name this capability.');
        }
        if (!$principal->carries($capability->permission)) {
            throw new AgentException(AgentException::CAPABILITY_NOT_GRANTED, sprintf('The token does not carry the permission "%s" the capability requires.', $capability->permission));
        }
        $grant = $this->grants->activeFor($principal->agent, $name);
        if ($grant === null) {
            throw new AgentException(AgentException::CAPABILITY_NOT_GRANTED, sprintf('The agent holds no active grant for "%s".', $name));
        }
        if (!$this->grants->ownerHolds($principal->agent, $capability->permission)) {
            throw new AgentException(AgentException::CAPABILITY_NOT_GRANTED, sprintf('The agent\'s owner no longer holds the permission "%s".', $capability->permission));
        }
        if (!is_array($arguments)) {
            throw new AgentException(AgentException::INVALID_ARGUMENTS, 'arguments is an object.', null, ['errors' => ['arguments is an object']]);
        }
        $this->validate($capability, $arguments);
        $violations = Constraints::violations($grant->constraints, $arguments);
        if ($violations !== []) {
            throw new AgentException(AgentException::CONSTRAINT_VIOLATED, 'The arguments violate the grant\'s constraints.', null, ['violations' => $violations]);
        }

        return new Evaluation($principal, $capability, $grant, $arguments, Receipts::inputHash($arguments), Constraints::cost($grant, $arguments));
    }

    /**
     * Spends the budget, runs the handler and appends the receipt in one transaction, holding the agent's
     * row from the start (so the kill switch and an execution serialise on it, and an agent revoked or
     * suspended meanwhile runs nothing); the handler's exception rolls everything back and is rethrown.
     *
     * @param callable(ExecutionContext): mixed $handler
     * @param (callable(mixed): string)|null $outcome the receipt's outcome from the handler's result (`success` by default)
     * @throws AgentException `agent_inactive`, `budget_exhausted`, `sealed`, `conflict`
     */
    public function run(Evaluation $evaluation, callable $handler, ?callable $outcome = null, ?string $ip = null, ?string $userAgent = null): Execution
    {
        $agent = $evaluation->principal->agent;
        $grant = $evaluation->grant;
        try {
            $execution = $this->database->transaction(function () use ($evaluation, $handler, $outcome, $agent, $grant): Execution {
                if ($this->database->update(Schema::AGENTS, ['id' => $agent->id, 'status' => Agent::STATUS_ACTIVE], ['updated_at' => $this->clock->now()]) !== 1) {
                    $status = (string) ($this->database->findOne(Schema::AGENTS, ['id' => $agent->id])['status'] ?? Agent::STATUS_REVOKED);
                    throw new AgentException(AgentException::AGENT_INACTIVE, 'The agent is ' . $status . '.', $status === Agent::STATUS_SUSPENDED ? 'agent_suspended' : 'agent_revoked');
                }
                $before = $grant->budgetRemaining;
                $after = null;
                if ($grant->budgetKind !== null) {
                    $after = $this->grants->spend($grant, $evaluation->cost);
                    if ($after === null) {
                        throw new AgentException(AgentException::BUDGET_EXHAUSTED, sprintf('The grant\'s budget cannot cover this execution (%d left).', (int) $before));
                    }
                }
                $result = $handler(new ExecutionContext($agent, $grant, $evaluation->capability, $evaluation->arguments, $evaluation->inputHash));
                $receipt = $this->receipts->append($agent, $grant, $evaluation->capability->name, $evaluation->inputHash, $outcome === null ? Receipt::OUTCOME_SUCCESS : $outcome($result), $before, $after);
                $exhausted = $after === 0;
                if ($exhausted) {
                    $this->grants->exhaust($grant);
                }

                return new Execution($result, $receipt, $grant, $exhausted);
            });
        } catch (AgentException $exception) {
            $this->deny($evaluation->principal, $evaluation->capability->name, $exception, $ip, $userAgent);
            throw $exception;
        }
        $this->events->dispatch(AgentEvent::byAgent(AuditNames::EXECUTED, $agent->id, $agent->subject(), $agent->organizationId, ['capability' => $evaluation->capability->name, 'receipt_id' => $execution->receipt->id, 'seq' => $execution->receipt->seq, 'outcome' => $execution->receipt->outcome], $ip, $userAgent));
        if ($execution->exhausted) {
            $this->grants->syncClientScopes($agent);
            $this->events->dispatch(AgentEvent::byAgent(AuditNames::GRANT_EXHAUSTED, $agent->id, $agent->subject(), $agent->organizationId, ['capability' => $grant->capability, 'grant_id' => $grant->id], $ip, $userAgent));
        }

        return $execution;
    }

    /**
     * `POST /agents/execute` and the MCP tools: the capability's configured handler.
     *
     * @throws AgentException
     */
    public function execute(AuthenticatedAgent $principal, string $name, mixed $arguments, ?string $ip = null, ?string $userAgent = null): Execution
    {
        try {
            $evaluation = $this->evaluate($principal, $name, $arguments);
        } catch (AgentException $exception) {
            $this->deny($principal, $name, $exception, $ip, $userAgent);
            throw $exception;
        }
        $handler = $evaluation->capability->handler;
        if ($handler === null) {
            $exception = new AgentException(AgentException::CAPABILITY_NOT_GRANTED, sprintf('"%s" runs at its location, %s, not here.', $name, (string) $evaluation->capability->location));
            $this->deny($principal, $name, $exception, $ip, $userAgent);
            throw $exception;
        }

        return $this->run($evaluation, static fn(ExecutionContext $context): mixed => $handler($context->arguments, $context), null, $ip, $userAgent);
    }

    /**
     * Records a refusal as `agent.execution_denied`.
     */
    public function deny(AuthenticatedAgent $principal, ?string $capability, AgentException $exception, ?string $ip = null, ?string $userAgent = null): void
    {
        $agent = $principal->agent;
        $this->events->dispatch(AgentEvent::byAgent(AuditNames::EXECUTION_DENIED, $agent->id, $agent->subject(), $agent->organizationId, ['capability' => $capability, 'error' => $exception->error, 'detail' => $exception->detail], $ip, $userAgent));
    }

    /**
     * A JSON Schema written as a PHP array, as opis reads it: associative arrays are objects, lists are
     * arrays, and an empty array under a keyword that takes an object (`properties`, `$defs`, ...) is `{}`.
     *
     * @param array<mixed> $schema
     */
    public static function schema(array $schema, ?string $keyword = null): stdClass|array
    {
        if ($schema === []) {
            return $keyword === null || in_array($keyword, self::OBJECT_KEYWORDS, true) ? new stdClass() : [];
        }
        if (array_is_list($schema)) {
            return array_map(static fn(mixed $item): mixed => is_array($item) ? self::schema($item) : $item, $schema);
        }
        $object = new stdClass();
        foreach ($schema as $key => $value) {
            $object->{$key} = is_array($value) ? self::schema($value, (string) $key) : $value;
        }

        return $object;
    }

    /**
     * @param array<string, mixed> $arguments
     * @throws AgentException `invalid_arguments`
     */
    private function validate(Capability $capability, array $arguments): void
    {
        // JSON objects, not PHP arrays: an empty argument set is `{}`, an empty schema any object.
        $data = $arguments === [] ? new stdClass() : json_decode(json_encode($arguments, JSON_THROW_ON_ERROR));
        $result = $this->validator->validate($data, self::schema($capability->input));
        if ($result->isValid()) {
            return;
        }
        $errors = [];
        $error = $result->error();
        if ($error !== null) {
            foreach ((new ErrorFormatter())->format($error, false) as $path => $message) {
                $errors[] = (is_string($path) && $path !== '/' ? $path . ': ' : '') . (is_string($message) ? $message : json_encode($message));
            }
        }

        throw new AgentException(AgentException::INVALID_ARGUMENTS, 'The arguments do not match the capability\'s input schema.', null, ['errors' => array_slice($errors, 0, self::MAX_ERRORS)]);
    }
}
