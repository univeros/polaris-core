<?php

declare(strict_types=1);

namespace Polaris\Agents;

use Polaris\Agents\Model\Agent;
use Polaris\Authorization\Gate;
use Polaris\Contract\TokenInterface;

use function array_filter;
use function array_values;
use function in_array;
use function is_array;
use function is_string;

/**
 * The agent a request authenticated as, and through which credential: a signed request JWT (with
 * the `capabilities` it may use, when it restricts them) or one of its OAuth access tokens (whose
 * delegated permissions bound what it may execute).
 */
final readonly class AuthenticatedAgent
{
    public const string VIA_JWT = 'jwt';
    public const string VIA_OAUTH = 'oauth';

    /**
     * @param list<string>|null $capabilities the JWT's `capabilities` claim, null for no restriction
     * @param list<string>|null $delegated the OAuth token's delegated permissions, null for a JWT
     */
    public function __construct(
        public Agent $agent,
        public string $via,
        public ?TokenInterface $token = null,
        public ?array $capabilities = null,
        public ?array $delegated = null,
    ) {
    }

    public static function viaJwt(Agent $agent, ?array $capabilities): self
    {
        return new self($agent, self::VIA_JWT, null, $capabilities);
    }

    public static function viaToken(Agent $agent, TokenInterface $token): self
    {
        $delegated = $token->getMetadata(Gate::DELEGATED);

        return new self($agent, self::VIA_OAUTH, $token, null, is_array($delegated) ? array_values(array_filter($delegated, is_string(...))) : []);
    }

    /**
     * Whether the credential lets the agent use the capability (its JWT names it, or names none).
     */
    public function mayUse(string $capability): bool
    {
        return $this->capabilities === null || in_array($capability, $this->capabilities, true);
    }

    /**
     * Whether the credential carries the permission (an OAuth token's scopes), or does not carry
     * scopes at all (a request JWT).
     */
    public function carries(string $permission): bool
    {
        return $this->delegated === null || in_array($permission, $this->delegated, true);
    }
}
