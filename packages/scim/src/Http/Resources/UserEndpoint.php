<?php

declare(strict_types=1);

namespace Polaris\Scim\Http\Resources;

use Polaris\Scim\Connections;
use Polaris\Scim\Http\ScimEndpoint;
use Polaris\Scim\ScimAudit;
use Polaris\Scim\Sp;
use Polaris\Scim\Users;

/**
 * The base of the `/Users` routes.
 */
abstract class UserEndpoint extends ScimEndpoint
{
    public function __construct(Connections $connections, ScimAudit $audit, Sp $sp, protected readonly Users $users)
    {
        parent::__construct($connections, $audit, $sp);
    }
}
