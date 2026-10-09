<?php

declare(strict_types=1);

namespace Polaris\Passkey\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\Passkey\Model\Passkey;
use Polaris\Passkey\PasskeyService;

use function array_map;

/**
 * `GET /passkey/list`: the caller's passkeys.
 */
final class ListEndpoint extends PasskeyEndpoint
{
    public function __construct(private readonly PasskeyService $passkeys)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        $token = $this->token($input);
        if ($token === null) {
            return $this->unauthorized();
        }

        return $this->respond(200, ['data' => array_map(static fn(Passkey $passkey): array => $passkey->toArray(), $this->passkeys->list($this->actorId($token)))]);
    }
}
