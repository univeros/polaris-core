<?php

declare(strict_types=1);

namespace Polaris\Scim\Model;

use DateTimeImmutable;

/**
 * A membership a connection created (`polaris_scim_membership_provenance`): the only ones it removes.
 */
final class Provenance
{
    public string $id = '';
    public string $organizationId = '';
    public string $userId = '';
    public string $connectionId = '';
    public DateTimeImmutable $createdAt;
}
