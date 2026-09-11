<?php

declare(strict_types=1);

namespace Polaris\Sso\Http\Flow;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `POST /sso/slo/{providerId}`: the POST binding (messages in the form body).
 */
final class SloPostEndpoint extends SloEndpoint
{
    #[Override]
    public function __invoke(Input $input): Result
    {
        return $this->singleLogout($input, deflated: false);
    }
}
