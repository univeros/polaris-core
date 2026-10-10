<?php

declare(strict_types=1);

namespace Polaris\Mcp;

use Polaris\Contract\TokenInterface;

/**
 * Who calls the MCP server: the token the credential resolved to (a session, an API key's owner, an
 * OAuth access token's user; null without one), the credential itself (re-sent only to the admin
 * plugin's routes, which authenticate from the header), and whether the admin plugin knows the caller
 * as an operator (an admin grant, a superadmin, an operator key).
 */
final readonly class Principal
{
    public function __construct(
        public ?TokenInterface $token = null,
        #[\SensitiveParameter] public ?string $credential = null,
        public bool $operator = false,
    ) {
    }

    public static function anonymous(): self
    {
        return new self();
    }
}
