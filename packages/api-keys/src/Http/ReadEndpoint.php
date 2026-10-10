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
 * `GET /api-keys/{id}`: one key of the caller's, or of an organization they may manage.
 */
final class ReadEndpoint extends ApiKeysEndpoint
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
            $key = $this->manageable($this->keys, $input, $token, $this->gate);
        } catch (ApiKeyException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(200, ['data' => $key->toArray($this->clock->now())]);
    }
}
