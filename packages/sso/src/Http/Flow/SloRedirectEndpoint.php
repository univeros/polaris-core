<?php

declare(strict_types=1);

namespace Polaris\Sso\Http\Flow;

use Override;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `GET /sso/slo/{providerId}`: the redirect binding (deflated messages in the query).
 */
final class SloRedirectEndpoint extends SloEndpoint
{
    #[Override]
    public function __invoke(Input $input): Result
    {
        return $this->singleLogout($input, deflated: true);
    }
}
