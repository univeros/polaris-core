<?php

declare(strict_types=1);

namespace Polaris\ApiKeys\Http;

use Override;
use Polaris\ApiKeys\ApiKeyException;
use Polaris\ApiKeys\AuditNames;
use Polaris\ApiKeys\Event\ApiKeyEvent;
use Polaris\ApiKeys\Keys;
use Polaris\Authorization\Gate;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * `DELETE /api-keys/{id}`: revokes a key; it stops authenticating at once.
 */
final class DeleteEndpoint extends ApiKeysEndpoint
{
    public function __construct(private readonly Keys $keys, private readonly Gate $gate, private readonly EventDispatcherInterface $events)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        try {
            $key = $this->manageable($this->keys, $input, $token, $this->gate);
        } catch (ApiKeyException $exception) {
            return $this->refuse($exception);
        }
        $this->keys->revoke($key);
        $client = $this->client($input);
        $this->events->dispatch(new ApiKeyEvent(AuditNames::REVOKED, $this->actorId($token), $key->id, $key->ownerType, $key->ownerId, $key->organizationId, ['name' => $key->name], $client->ip, $client->userAgent));

        return $this->respond(200, ['data' => ['status' => 'revoked']]);
    }
}
