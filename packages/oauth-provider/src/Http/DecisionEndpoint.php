<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\AuditNames;
use Polaris\OAuth\Authorization;
use Polaris\OAuth\Event\OAuthEvent;
use Polaris\OAuth\OAuthException;
use Psr\EventDispatcher\EventDispatcherInterface;

use function is_int;

/**
 * `POST /oauth2/authorize/decision`: the signed-in user approves or refuses a parked request; the
 * answer is where the browser goes next (the redirect URI with the code, or with the refusal). A
 * trusted client, or scopes already granted, need no approval: `approve` may be omitted and the code
 * is minted; otherwise `consent_required` says a screen is needed.
 */
final class DecisionEndpoint extends OAuthEndpoint
{
    public function __construct(private readonly Authorization $authorization, private readonly EventDispatcherInterface $events)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        $userId = $this->actorId($token);
        try {
            [$request, $client] = $this->authorization->pending(self::text($input, 'request'));
            $approve = $input->get('approve');
            if ($approve === null && $this->authorization->needsConsent($request, $client, $userId)) {
                throw new OAuthException(OAuthException::CONSENT_REQUIRED, 'The user must approve the scopes: answer with approve true or false.', 409);
            }
            $approve = $approve === null ? true : $approve === true;
            $authTime = $token->getMetadata('auth_time');
            [$url, $recorded] = $this->authorization->decide($request, $client, $userId, $this->actorOrg($token), $approve, is_int($authTime) ? $authTime : null);
        } catch (OAuthException $exception) {
            return $this->refuse($exception);
        }
        $clientContext = $this->client($input);
        $this->events->dispatch(new OAuthEvent($approve ? AuditNames::CONSENT_GRANTED : AuditNames::CONSENT_DENIED, $userId, $client->clientId, $this->actorOrg($token), ['scopes' => $request->scopes, 'recorded' => $recorded], $clientContext->ip, $clientContext->userAgent));

        return new Result(200, ['data' => ['redirect_to' => $url, 'approved' => $approve]], self::NO_STORE);
    }
}
