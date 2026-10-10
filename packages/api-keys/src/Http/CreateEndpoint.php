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

use function is_array;
use function is_string;

use const DATE_ATOM;

/**
 * `POST /api-keys`: a key for the caller, or for an organization they may manage; the secret is in
 * this response only.
 */
final class CreateEndpoint extends ApiKeysEndpoint
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
        $permissions = $input->get('permissions', []);
        $rateLimit = $input->get('rate_limit');
        $metadata = $input->get('metadata', []);
        $expiresAt = self::datetime($input->get('expires_at'));
        if (!is_array($permissions) || ($rateLimit !== null && !is_array($rateLimit)) || !is_array($metadata) || $expiresAt === false) {
            return $this->problem(422, 'api-keys/invalid_input', 'Invalid input', 'permissions is a list, rate_limit an object with window and max, metadata an object, expires_at a date.', ['errors' => ['invalid input']]);
        }
        $environment = $input->get('environment');
        try {
            [$ownerType, $ownerId, $organizationId] = $this->owner($input, $token, $this->gate);
            $issued = $this->keys->create(
                $ownerType,
                $ownerId,
                $organizationId,
                $this->actorId($token),
                (string) $input->get('name', ''),
                $permissions,
                $this->held($token, $this->gate, $organizationId),
                is_string($environment) ? $environment : null,
                $rateLimit,
                $expiresAt,
                $metadata,
            );
        } catch (ApiKeyException $exception) {
            return $this->refuse($exception);
        }
        $key = $issued->key;
        $client = $this->client($input);
        $this->events->dispatch(new ApiKeyEvent(AuditNames::CREATED, $this->actorId($token), $key->id, $key->ownerType, $key->ownerId, $key->organizationId, ['name' => $key->name, 'permissions' => $key->permissions, 'expires_at' => $key->expiresAt?->format(DATE_ATOM)], $client->ip, $client->userAgent));

        return $this->respond(201, ['data' => [...$key->toArray($this->clock->now()), 'key' => $issued->secret]]);
    }
}
