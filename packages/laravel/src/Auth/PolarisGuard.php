<?php

declare(strict_types=1);

namespace Polaris\Laravel\Auth;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;
use Override;
use Polaris\Exception\AuthorizationTokenException;
use Polaris\Wiring\Graph;

use function is_string;

/**
 * The `polaris` guard driver for the application's own routes: a valid `Authorization: Bearer` access
 * token, verified by the Polaris token factory, identifies a {@see PolarisUser}. Nothing else
 * authenticates through it: login is the endpoints' job, so `validate()` is always false.
 */
final class PolarisGuard implements Guard
{
    use GuardHelpers;

    public function __construct(private readonly Graph $graph, private Request $request)
    {
    }

    #[Override]
    public function user(): ?Authenticatable
    {
        if ($this->user !== null) {
            return $this->user;
        }
        $bearer = $this->request->bearerToken();
        if (!is_string($bearer) || $bearer === '') {
            return null;
        }
        try {
            $token = $this->graph->tokenFactory()->fromTokenString($bearer);
        } catch (AuthorizationTokenException) {
            return null;
        }
        $subject = $token->getMetadata('sub');
        $user = is_string($subject) ? $this->graph->users()->find($subject) : null;
        if ($user === null) {
            return null;
        }

        return $this->user = new PolarisUser($user, $token);
    }

    #[Override]
    public function validate(array $credentials = []): bool
    {
        return false;
    }

    public function setRequest(Request $request): static
    {
        $this->request = $request;

        return $this;
    }
}
