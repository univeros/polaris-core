<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Model\User;
use Polaris\OAuth\OAuthResolver;
use Polaris\OAuth\Scopes;
use Polaris\Repository\UserRepository;

use function in_array;
use function is_string;
use function preg_split;

/**
 * `GET /oauth2/userinfo` (and `POST`): the OpenID claims the token's scopes allow about its user. The
 * bearer is one of this provider's access tokens with `openid` (core's bearer resolver verified it,
 * DPoP binding included).
 */
class UserinfoEndpoint extends OAuthEndpoint
{
    public function __construct(private readonly UserRepository $users)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        $scope = $token->getMetadata(OAuthResolver::CLAIM_SCOPE);
        $scopes = is_string($scope) ? (preg_split('/\s+/', $scope) ?: []) : [];
        $user = $this->users->find($this->actorId($token));
        if (!in_array(OAuthResolver::AMR, (array) $token->getMetadata('amr'), true) || !in_array(Scopes::OPENID, $scopes, true) || !$user instanceof User) {
            return new Result(401, ['error' => 'invalid_token', 'error_description' => 'An access token with the openid scope is required.'], ['WWW-Authenticate' => 'Bearer error="invalid_token", error_description="An access token with the openid scope is required."', ...self::NO_STORE]);
        }

        return new Result(200, ['sub' => $user->id, ...Scopes::claims($user, $scopes)], self::NO_STORE);
    }
}
