<?php

declare(strict_types=1);

namespace Polaris\Scim\Model;

use DateTimeImmutable;

/**
 * The directory's external id of a user or a group (a role) under one connection (`polaris_scim_resource`).
 */
final class Resource
{
    public const string USER = 'User';
    public const string GROUP = 'Group';

    public string $id = '';
    public string $connectionId = '';
    public string $kind = self::USER;
    public string $externalId = '';
    public string $localId = '';
    public DateTimeImmutable $updatedAt;
}
