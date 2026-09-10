<?php

declare(strict_types=1);

namespace Polaris\Yii\Auth;

use Override;
use Polaris\Exception\AuthorizationTokenException;
use Polaris\Wiring\Graph;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Yiisoft\Auth\AuthenticationMethodInterface;
use Yiisoft\Auth\IdentityInterface;

use function is_string;
use function preg_match;
use function trim;

/**
 * The authentication method for the application's own routes (`yiisoft/auth`'s `Authentication`
 * middleware, wired as `polaris/authentication`): a valid `Authorization: Bearer` access token, verified
 * by the Polaris token factory, identifies a {@see PolarisIdentity}. Nothing else authenticates through
 * it: login is the endpoints' job. The challenge is `WWW-Authenticate: Bearer`.
 */
final readonly class PolarisAuthenticationMethod implements AuthenticationMethodInterface
{
    public function __construct(private Graph $graph)
    {
    }

    #[Override]
    public function authenticate(ServerRequestInterface $request): ?IdentityInterface
    {
        if (preg_match('/^Bearer\s+(\S.*)$/i', $request->getHeaderLine('Authorization'), $matches) !== 1) {
            return null;
        }
        try {
            $token = $this->graph->tokenFactory()->fromTokenString(trim($matches[1]));
        } catch (AuthorizationTokenException) {
            return null;
        }
        $subject = $token->getMetadata('sub');
        $user = is_string($subject) ? $this->graph->users()->find($subject) : null;

        return $user === null ? null : new PolarisIdentity($user, $token);
    }

    #[Override]
    public function challenge(ResponseInterface $response): ResponseInterface
    {
        return $response->withHeader('WWW-Authenticate', 'Bearer');
    }
}
