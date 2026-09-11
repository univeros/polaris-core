<?php

declare(strict_types=1);

namespace Polaris\Audit\Http;

use Override;
use Polaris\Audit\Query\AuditQuery;
use Polaris\Audit\Store;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `GET /audit/me`: the events where the caller is the actor or the subject, newest first.
 */
final class MeEndpoint extends AuditEndpoint
{
    public function __construct(private readonly Store $store)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        $query = $this->query($input, principalId: $this->actorId($token));
        if (!$query instanceof AuditQuery) {
            return $query;
        }

        return $this->respond(200, $this->store->read($query)->toArray());
    }
}
