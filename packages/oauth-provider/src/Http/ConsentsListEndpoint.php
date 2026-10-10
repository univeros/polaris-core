<?php

declare(strict_types=1);

namespace Polaris\OAuth\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\OAuth\Clients;
use Polaris\OAuth\Consents;

/**
 * `GET /oauth2/consents`: the clients the caller granted scopes to.
 */
final class ConsentsListEndpoint extends OAuthEndpoint
{
    public function __construct(private readonly Consents $consents, private readonly Clients $clients)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }
        $data = [];
        foreach ($this->consents->forUser($this->actorId($token)) as $consent) {
            $data[] = [...$consent->toArray(), 'client' => $this->clients->find($consent->clientId)?->toPublicArray()];
        }

        return $this->respond(200, ['data' => $data]);
    }
}
