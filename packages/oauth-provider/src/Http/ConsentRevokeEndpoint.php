<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\AuditNames;
use Polaris\OAuth\Consents;
use Polaris\OAuth\Event\OAuthEvent;
use Polaris\OAuth\Tokens;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * `DELETE /oauth2/consents/{clientId}`: the caller takes a client's consent back; every token the
 * client holds for them is revoked.
 */
final class ConsentRevokeEndpoint extends OAuthEndpoint
{
    public function __construct(private readonly Consents $consents, private readonly Tokens $tokens, private readonly EventDispatcherInterface $events)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        $clientId = (string) $input->get('clientId');
        $userId = $this->actorId($token);
        if (!$this->consents->revoke($userId, $clientId)) {
            return $this->problem(404, 'oauth/not_found', 'Not found', 'You have not granted that client anything.');
        }
        $revoked = $this->tokens->revokeForUserAndClient($userId, $clientId);
        $context = $this->client($input);
        $this->events->dispatch(new OAuthEvent(AuditNames::CONSENT_REVOKED, $userId, $clientId, $this->actorOrg($token), ['tokens_revoked' => $revoked], $context->ip, $context->userAgent));

        return $this->respond(200, ['data' => ['status' => 'revoked', 'tokens_revoked' => $revoked]]);
    }
}
