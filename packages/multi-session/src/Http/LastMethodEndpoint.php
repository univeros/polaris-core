<?php

declare(strict_types=1);

namespace Polaris\MultiSession\Http;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;
use Polaris\MultiSession\Devices;

/**
 * `GET /multi-session/last-method`: how the device last signed in, for the client to pre-select the
 * button; no personal data, so no session needed.
 */
final class LastMethodEndpoint extends MultiSessionEndpoint
{
    public function __construct(private readonly Devices $devices)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        return $this->respond(200, ['data' => ['last_method' => $this->devices->lastMethod(self::device($input))]]);
    }
}
