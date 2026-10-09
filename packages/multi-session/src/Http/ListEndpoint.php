<?php

declare(strict_types=1);

namespace Polaris\MultiSession\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\MultiSession\Devices;
use Polaris\MultiSession\MultiSessionException;

/**
 * `GET /multi-session/list`: the accounts signed in on the caller's device.
 */
final class ListEndpoint extends MultiSessionEndpoint
{
    public function __construct(private readonly Devices $devices)
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
            $sessions = $this->devices->list(self::device($input), self::sessionId($token));
        } catch (MultiSessionException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(200, ['data' => $sessions]);
    }
}
