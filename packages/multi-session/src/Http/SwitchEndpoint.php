<?php

declare(strict_types=1);

namespace Polaris\MultiSession\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\MultiSession\Devices;
use Polaris\MultiSession\MultiSessionException;

use function is_string;

/**
 * `POST /multi-session/switch`: a fresh session for another account of the device, without signing in.
 */
final class SwitchEndpoint extends MultiSessionEndpoint
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
        $sessionId = $input->get('session_id');
        if (!is_string($sessionId) || $sessionId === '') {
            return $this->problem(422, 'multi-session/invalid_input', 'Invalid input', 'session_id is required.', ['errors' => ['session_id is required.']]);
        }
        try {
            $envelope = $this->devices->switch(self::device($input), self::sessionId($token), $sessionId, $this->client($input));
        } catch (MultiSessionException $exception) {
            return $this->refuse($exception);
        }

        return $this->respond(200, ['data' => $envelope]);
    }
}
