<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\AuditNames;
use Polaris\OAuth\Ciba;
use Polaris\OAuth\Event\OAuthEvent;
use Polaris\OAuth\OAuthException;
use Psr\EventDispatcher\EventDispatcherInterface;

use function is_int;

/**
 * `POST /oauth2/ciba/{id}/decide`: the user approves (`approve: true`) or refuses a backchannel
 * request addressed to them.
 */
final class CibaDecideEndpoint extends OAuthEndpoint
{
    public function __construct(private readonly Ciba $ciba, private readonly EventDispatcherInterface $events)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        $approve = $input->get('approve') === true;
        try {
            $authTime = $token->getMetadata('auth_time');
            $request = $this->ciba->decide((string) $input->get('id'), $this->actorId($token), $approve, $this->actorOrg($token), is_int($authTime) ? $authTime : null);
        } catch (OAuthException $exception) {
            return $this->refuse($exception);
        }
        $context = $this->client($input);
        $this->events->dispatch(new OAuthEvent(AuditNames::CIBA_DECIDED, $this->actorId($token), $request->clientId, $this->actorOrg($token), ['approved' => $approve, 'auth_req_id' => $request->id], $context->ip, $context->userAgent));

        return new Result(200, ['data' => ['status' => $request->status]], self::NO_STORE);
    }
}
