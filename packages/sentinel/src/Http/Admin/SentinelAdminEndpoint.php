<?php

declare(strict_types=1);

namespace Polaris\Sentinel\Http\Admin;

use Polaris\Admin\Http\AdminRoute;
use Polaris\Http\Endpoint;

/**
 * The base of the routes under `/admin/sentinel`: `polaris/admin`'s principal, capability check and problems.
 */
abstract class SentinelAdminEndpoint extends Endpoint
{
    use AdminRoute;
}
