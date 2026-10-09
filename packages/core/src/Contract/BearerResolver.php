<?php

declare(strict_types=1);

namespace Polaris\Contract;

use Polaris\Exception\AuthorizationTokenException;
use Psr\Http\Message\ServerRequestInterface;

/**
 * A plugin's way of authenticating a request on the routes core guards with a bearer (`auth: bearer`):
 * asked before core parses the `Authorization: Bearer` JWT, it answers the {@see TokenInterface} the
 * request authenticates as (`polaris/api-keys` answers the key's owner for `Bearer pk_...` or
 * `x-api-key`), null when the request carries nothing it recognises, so the next resolver or core's
 * parser decides. The token's `sub`, `org`, `iat` and `jti` are read as a session's would be; a
 * `delegated` metadata restricts the authority the {@see \Polaris\Authorization\Gate} resolves for it.
 * Registered by a plugin implementing {@see BearerResolverProvider}; consulted on the pipeline's
 * routes only, never by `TokenFactoryInterface`, so a host's own guard keeps seeing core sessions.
 */
interface BearerResolver
{
    /**
     * @throws AuthorizationTokenException the request carries a credential of this resolver's kind that
     *                                     does not authenticate (revoked, expired, over its limit)
     */
    public function resolve(ServerRequestInterface $request): ?TokenInterface;
}
