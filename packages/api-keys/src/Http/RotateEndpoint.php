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
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

use function array_fill_keys;
use function sprintf;

use const DATE_ATOM;

/**
 * `POST /api-keys/{id}/rotate`: a successor with a new secret (in this response only); the key named
 * keeps answering until the grace window ends.
 */
final class RotateEndpoint extends ApiKeysEndpoint
{
    public function __construct(
        private readonly Keys $keys,
        private readonly Gate $gate,
        private readonly EventDispatcherInterface $events,
        private readonly ClockInterface $clock,
    ) {
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
            if ($key->createdBy !== $this->actorId($token)) {
                // The successor acts as the creator: another admin may rotate it only within what they hold themselves.
                $held = array_fill_keys($this->held($token, $this->gate, $key->organizationId), true);
                foreach ($key->permissions as $permission) {
                    if (!isset($held[$permission])) {
                        throw new ApiKeyException(ApiKeyException::PERMISSION_NOT_HELD, sprintf('The key holds "%s", which you do not; its creator rotates it.', $permission));
                    }
                }
            }
            $issued = $this->keys->rotate($key);
        } catch (ApiKeyException $exception) {
            return $this->refuse($exception);
        }
        $client = $this->client($input);
        $this->events->dispatch(new ApiKeyEvent(AuditNames::ROTATED, $this->actorId($token), $key->id, $key->ownerType, $key->ownerId, $key->organizationId, ['successor' => $issued->key->id, 'grace_until' => $key->graceUntil?->format(DATE_ATOM)], $client->ip, $client->userAgent));

        return $this->respond(201, ['data' => [...$issued->key->toArray($this->clock->now()), 'key' => $issued->secret]]);
    }
}
