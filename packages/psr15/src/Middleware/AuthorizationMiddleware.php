<?php

declare(strict_types=1);

namespace Polaris\Psr15\Middleware;

use Override;
use Polaris\Authorization\Gate;
use Polaris\Contract\TokenInterface;
use Polaris\Http\Attributes;
use Polaris\Http\Manifest\EndpointSpec;
use Polaris\Psr15\JsonResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

use function constant;
use function defined;
use function is_array;
use function is_string;

/**
 * Database-resolved authorization: when the routed endpoint declares `REQUIRES_PERMISSIONS`,
 * the caller's verified authority must grant every one of them.
 */
final class AuthorizationMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly Gate $gate,
        private readonly UnauthorizedResponder $unauthorized,
        private readonly JsonResponse $json,
    ) {
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $spec = $request->getAttribute(Attributes::ROUTE);
        $required = $spec instanceof EndpointSpec ? self::requiredPermissions($spec) : [];
        if ($required === []) {
            return $handler->handle($request);
        }
        $token = $request->getAttribute(Attributes::TOKEN);
        if (!$token instanceof TokenInterface) {
            return $this->unauthorized->respond();
        }
        $authority = $this->gate->authority($token);
        if (!$this->gate->allowsAuthority($authority, ...$required)) {
            return $this->json->error(403, 'forbidden', 'You do not have permission to perform this action.');
        }

        return $handler->handle($request->withAttribute(Attributes::AUTHORITY, $authority));
    }

    /**
     * @return list<string>
     */
    public static function requiredPermissions(EndpointSpec $spec): array
    {
        $constant = $spec->class . '::REQUIRES_PERMISSIONS';
        if (!defined($constant)) {
            return [];
        }
        $permissions = [];
        foreach ((array) constant($constant) as $permission) {
            if (is_string($permission)) {
                $permissions[] = $permission;
            }
        }

        return $permissions;
    }
}
