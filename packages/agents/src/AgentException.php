<?php

declare(strict_types=1);

namespace Polaris\Agents;

use RuntimeException;

use function in_array;
use function str_replace;
use function ucwords;

/**
 * A refused agent request, answered as an RFC 9457 problem `agents/<type>` whose `error` member carries
 * the Agent Auth Protocol code where one exists (`invalid_jwt`, `aud_mismatch`, `agent_revoked`,
 * `capability_not_found`, `capability_not_granted`, `constraint_violated`, `budget_exhausted`).
 */
final class AgentException extends RuntimeException
{
    public const string UNAUTHORIZED = 'unauthorized';
    public const string INVALID_JWT = 'invalid_jwt';
    public const string AUD_MISMATCH = 'aud_mismatch';
    public const string AGENT_INACTIVE = 'agent_inactive';
    public const string CAPABILITY_NOT_FOUND = 'capability_not_found';
    public const string CAPABILITY_NOT_GRANTED = 'capability_not_granted';
    public const string CONSTRAINT_VIOLATED = 'constraint_violated';
    public const string BUDGET_EXHAUSTED = 'budget_exhausted';
    public const string UNKNOWN_CONSTRAINT_OPERATOR = 'unknown_constraint_operator';
    public const string INVALID_ARGUMENTS = 'invalid_arguments';
    public const string INVALID_INPUT = 'invalid_input';
    public const string NOT_FOUND = 'not_found';
    public const string FORBIDDEN = 'forbidden';
    public const string CONFLICT = 'conflict';
    public const string STEP_UP_REQUIRED = 'step_up_required';
    public const string PERMISSION_NOT_HELD = 'permission_not_held';
    public const string SEALED = 'sealed';
    /** The codes the Agent Auth Protocol defines or Polaris's protocol document adds; the others are Polaris's own. */
    public const array PROTOCOL_CODES = [self::INVALID_JWT, self::AUD_MISMATCH, self::AGENT_INACTIVE, self::CAPABILITY_NOT_FOUND, self::CAPABILITY_NOT_GRANTED, self::CONSTRAINT_VIOLATED, self::BUDGET_EXHAUSTED, self::UNKNOWN_CONSTRAINT_OPERATOR];

    private const array STATUSES = [
        self::UNAUTHORIZED => 401,
        self::INVALID_JWT => 401,
        self::AUD_MISMATCH => 401,
        self::AGENT_INACTIVE => 401,
        self::CAPABILITY_NOT_FOUND => 404,
        self::CAPABILITY_NOT_GRANTED => 403,
        self::CONSTRAINT_VIOLATED => 403,
        self::BUDGET_EXHAUSTED => 403,
        self::UNKNOWN_CONSTRAINT_OPERATOR => 400,
        self::INVALID_ARGUMENTS => 422,
        self::INVALID_INPUT => 422,
        self::NOT_FOUND => 404,
        self::FORBIDDEN => 403,
        self::CONFLICT => 409,
        self::STEP_UP_REQUIRED => 403,
        self::PERMISSION_NOT_HELD => 403,
        self::SEALED => 409,
    ];

    public readonly int $status;
    public readonly string $error;

    /**
     * @param string|null $error the AAP code when it differs from the type (`agent_revoked`, `agent_suspended`)
     * @param array<string, mixed> $extensions further problem members (`violations`, `errors`)
     */
    public function __construct(public readonly string $type, public readonly string $detail, ?string $error = null, public readonly array $extensions = [])
    {
        parent::__construct($type . ': ' . $detail);
        $this->status = self::STATUSES[$type] ?? 400;
        // The protocol's own codes travel bare (agent-auth-compat.md); Polaris's own carry the plugin's prefix
        // as every plugin's `error` does (`api_keys_not_found`), matching the codes the manifest declares.
        $this->error = $error ?? (in_array($type, self::PROTOCOL_CODES, true) ? $type : 'agents_' . $type);
    }

    /**
     * The RFC 9457 body, as {@see \Polaris\Http\Endpoint::problem()} shapes it, plus the AAP `error`.
     *
     * @return array<string, mixed>
     */
    public function toProblem(): array
    {
        return [
            'type' => 'https://polaris.univeros.io/problems/agents/' . $this->type,
            'title' => ucwords(str_replace('_', ' ', $this->type)),
            'status' => $this->status,
            'detail' => $this->detail,
            'error' => $this->error,
            'message' => $this->detail,
            ...$this->extensions,
        ];
    }
}
