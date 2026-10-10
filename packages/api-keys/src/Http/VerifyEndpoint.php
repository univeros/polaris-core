<?php

declare(strict_types=1);

namespace Polaris\ApiKeys\Http;

use Override;
use Polaris\ApiKeys\Keys;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Psr\Clock\ClockInterface;

use function is_string;

use const DATE_ATOM;

/**
 * `POST /api-keys/verify`: the server-side check for an application that proxies: whether the key
 * authenticates right now, and whose and what it may do when it does. Never the key's hash.
 */
final class VerifyEndpoint extends ApiKeysEndpoint
{
    public function __construct(private readonly Keys $keys, private readonly ClockInterface $clock)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        if ($this->token($input) === null) {
            return $this->unauthorized();
        }
        $secret = $input->get('key');
        if (!is_string($secret) || $secret === '') {
            return $this->problem(422, 'api-keys/invalid_input', 'Invalid input', 'key is required.', ['errors' => ['key is required']]);
        }
        $key = $this->keys->authenticate($secret);
        if ($key === null) {
            return $this->respond(200, ['data' => ['valid' => false]]);
        }

        return $this->respond(200, ['data' => [
            'valid' => true,
            'id' => $key->id,
            'name' => $key->name,
            'owner_type' => $key->ownerType,
            'owner_id' => $key->ownerId,
            'organization_id' => $key->organizationId,
            'subject' => $key->subject(),
            'permissions' => $key->permissions,
            'rate_limit' => $key->rateLimit(),
            'metadata' => (object) $key->metadata,
            'status' => $key->status($this->clock->now()),
            'expires_at' => $key->expiresAt?->format(DATE_ATOM),
        ]]);
    }
}
