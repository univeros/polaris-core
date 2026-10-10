<?php

declare(strict_types=1);

namespace Polaris\ApiKeys\Http;

use Override;
use Polaris\ApiKeys\ApiKeyException;
use Polaris\ApiKeys\Keys;
use Polaris\Authorization\Gate;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Psr\Clock\ClockInterface;

/**
 * `GET /api-keys`: the caller's keys, or an organization's with `?organization_id=`.
 */
final class ListEndpoint extends ApiKeysEndpoint
{
    public function __construct(private readonly Keys $keys, private readonly Gate $gate, private readonly ClockInterface $clock)
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
            [$ownerType, $ownerId] = $this->owner($input, $token, $this->gate);
        } catch (ApiKeyException $exception) {
            return $this->refuse($exception);
        }
        $now = $this->clock->now();
        $data = [];
        foreach ($this->keys->forOwner($ownerType, $ownerId) as $key) {
            $data[] = $key->toArray($now);
        }

        return $this->respond(200, ['data' => $data]);
    }
}
