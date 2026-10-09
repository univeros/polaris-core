<?php

declare(strict_types=1);

namespace Polaris\MultiSession\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\MultiSession\Devices;
use Polaris\MultiSession\MultiSessionException;

/**
 * `DELETE /multi-session/{sessionId}`: ends one of the device's sessions; the others stay.
 */
final class RevokeEndpoint extends MultiSessionEndpoint
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
            $this->devices->revoke(self::device($input), self::sessionId($token), (string) $input->get('sessionId'));
        } catch (MultiSessionException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(200, ['data' => ['status' => 'revoked']]);
    }
}
