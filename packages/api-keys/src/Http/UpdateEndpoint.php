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

/**
 * `PATCH /api-keys/{id}`: the name, permissions (still a subset of the owner's), rate limit, expiry or
 * metadata of a key; a field left out keeps its value, `rate_limit: null` and `expires_at: null` clear.
 */
final class UpdateEndpoint extends ApiKeysEndpoint
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
        $name = $input->get('name');
        $permissions = $input->get('permissions');
        $rateLimit = $input->has('rate_limit') ? $input->get('rate_limit') : false;
        $metadata = $input->get('metadata');
        $expiresAt = $input->has('expires_at') ? self::datetime($input->get('expires_at')) : false;
        $invalid = ($name !== null && !is_string($name))
            || ($permissions !== null && !is_array($permissions))
            || ($rateLimit !== false && $rateLimit !== null && !is_array($rateLimit))
            || ($metadata !== null && !is_array($metadata))
            || ($input->has('expires_at') && $expiresAt === false);
        if ($invalid) {
            return $this->problem(422, 'api-keys/invalid_input', 'Invalid input', 'name is a string, permissions a list, rate_limit an object with window and max or null, metadata an object, expires_at a date or null.', ['errors' => ['invalid input']]);
        }
        try {
            $key = $this->manageable($this->keys, $input, $token, $this->gate);
            $held = $permissions === null ? [] : $this->held($token, $this->gate, $key->organizationId);
            $changes = $this->keys->update($key, $held, $name, $permissions, $rateLimit, $expiresAt, $metadata);
        } catch (ApiKeyException $exception) {
            return $this->refuse($exception);
        }
        if ($changes !== []) {
            $client = $this->client($input);
            $this->events->dispatch(new ApiKeyEvent(AuditNames::UPDATED, $this->actorId($token), $key->id, $key->ownerType, $key->ownerId, $key->organizationId, ['changes' => $changes], $client->ip, $client->userAgent));
        }

        return $this->respond(200, ['data' => $key->toArray($this->clock->now())]);
    }
}
