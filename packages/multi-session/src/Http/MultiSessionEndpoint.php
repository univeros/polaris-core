<?php

declare(strict_types=1);

namespace Polaris\MultiSession\Http;

use Polaris\Contract\TokenInterface;
use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\MultiSession\MultiSessionException;

use function is_string;

/**
 * What the multi-session routes share: the device the middleware accepted, the caller's session and the
 * problem document for a refused step.
 */
abstract class MultiSessionEndpoint extends Endpoint
{
    protected static function device(Input $input): ?string
    {
        $device = $input->attribute(DeviceMiddleware::ATTRIBUTE);

        return is_string($device) ? $device : null;
    }

    protected static function sessionId(TokenInterface $token): string
    {
        $sid = $token->getMetadata('sid');

        return is_string($sid) ? $sid : '';
    }

    protected function refuse(MultiSessionException $exception): Result
    {
        return $exception->reason === MultiSessionException::DEVICE_UNKNOWN
            ? $this->problem(403, 'multi-session/device_unknown', 'Device unknown', $exception->getMessage())
            : $this->problem(404, 'multi-session/session_not_found', 'Session not found', $exception->getMessage());
    }
}
