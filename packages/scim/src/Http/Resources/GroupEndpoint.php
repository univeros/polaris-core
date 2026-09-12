<?php

declare(strict_types=1);

namespace Polaris\Scim\Http\Resources;

use Polaris\Scim\Connections;
use Polaris\Scim\Groups;
use Polaris\Scim\Http\ScimEndpoint;
use Polaris\Scim\ScimAudit;
use Polaris\Scim\Sp;

/**
 * The base of the `/Groups` routes.
 */
abstract class GroupEndpoint extends ScimEndpoint
{
    public function __construct(Connections $connections, ScimAudit $audit, Sp $sp, protected readonly Groups $groups)
    {
        parent::__construct($connections, $audit, $sp);
    }
}
