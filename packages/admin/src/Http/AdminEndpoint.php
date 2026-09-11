<?php

declare(strict_types=1);

namespace Polaris\Admin\Http;

use Polaris\Http\Endpoint;

/**
 * The base of the admin endpoints (the audit query one extends the audit package's base instead).
 */
abstract class AdminEndpoint extends Endpoint
{
    use AdminRoute;
}
